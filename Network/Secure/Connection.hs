module Network.Secure.Connection
    (
      HostName
    , ServiceName

    , Connection
    , peer
    , Network.Secure.Connection.connect
    , Network.Secure.Connection.read
    , Network.Secure.Connection.write
    , Network.Secure.Connection.readPtr
    , Network.Secure.Connection.writePtr
    , Network.Secure.Connection.close

    , Network.Secure.Connection.Socket
    , newServer
    , Network.Secure.Connection.accept
    ) where

import Prelude hiding (read)

import Control.Applicative ((<$>))
import Control.Exception (bracketOnError, onException)
import Control.Monad (liftM, unless)
import Data.ByteString (ByteString)
import Data.Maybe (fromJust)
import OpenSSL.Session (ShutdownType(Unidirectional), SSLContext, SSL,
                        VerificationMode(VerifyPeer), accept, connect,
                        connection, context, contextSetPrivateKey,
                        contextSetCertificate, contextSetCiphers,
                        contextSetVerificationMode, contextGetCAStore,
                        getPeerCertificate, getVerifyResult, read, shutdown,
                        write, readPtr, writePtr)
import OpenSSL.X509 (compareX509)
import OpenSSL.X509.Store (addCertToStore)
import Network.Socket hiding (shutdown)

import Network.Secure.Identity
import Foreign.Ptr(Ptr)

-- |An established authenticated connection to a peer. It is
-- guaranteed that all Connection objects are with a known peer, and
-- that the connection is strongly encrypted.
data Connection = C
    {
      ssl   :: SSL
      -- |Return the 'PeerIdentity' of the remote end of the connection.
    , peer  :: PeerIdentity
    , _addr :: SockAddr
    }

instance Eq Connection where
    (C _ p1 a1) == (C _ p2 a2) = (p1, a1) == (p2, a2)

instance Show Connection where
    show (C _ p a) = concat [ "Connection { peer = "
                            , show p
                            , ", addr = "
                            , show a
                            , " }" ]

-- |A server socket that accepts only secure connections.
newtype Socket = S { 
    unSocket :: Network.Socket.Socket
    } deriving (Eq, Show)

-- |Connect securely to the given host/port. The 'Connection' is
-- returned only if the peer accepts the given 'LocalIdentity', and if
-- the remote endpoint successfully authenticates as one of the given
-- 'PeerIdentity'.
connect :: LocalIdentity -> [PeerIdentity] -> (HostName, ServiceName)
        -> IO Connection
connect myId peerIds (host, port) =
  do info <- getSockAddr (Just host) port
     bracketOnError (newSock info) sClose $ \sock -> do
        setSocketOption sock ReuseAddr 1
        Network.Socket.connect sock (addrAddress info)
        r <- connectSSL myId peerIds False sock
        return r

-- |Read at most 'n' bytes from the given connection.
read :: Connection -> Int -> IO ByteString
read = OpenSSL.Session.read . ssl

-- |Send data to the connected peer.
write :: Connection -> ByteString -> IO ()
write = OpenSSL.Session.write . ssl

-- |Read at most 'n' bytes from the given connection, into the given raw buffer.
readPtr :: Connection -> Ptr a -> Int -> IO Int
readPtr c p n = OpenSSL.Session.readPtr (ssl c) p n

-- |Send data from the given raw pointer to the connected peer.
writePtr :: Connection -> Ptr a -> Int -> IO ()
writePtr c p n = OpenSSL.Session.writePtr (ssl c) p n

-- |Close the connection. No other operations on 'Connection's should
-- be used after closing it.
close :: Connection -> IO ()
close conn = shutdown (ssl conn) Unidirectional

-- |Create a new secure socket server, listening on the given
-- address/port. The host may be 'Nothing' to signify that the socket
-- should listen on all available addresses.
newServer :: (Maybe HostName, ServiceName)
          -> IO Network.Secure.Connection.Socket
newServer (host, port) = do
    info <- getSockAddr host port
    sock <- newSock info
    setSocketOption sock ReuseAddr 1
    bindSocket sock (addrAddress info)
    listen sock 10
    return $ S sock

-- |Accept one secure connection from a remote peer. The peer may
-- authenticate as any of the given peer identities. A 'Connection' is
-- returned iff the autentication completes successfully.
accept :: LocalIdentity -> [PeerIdentity] -> Network.Secure.Connection.Socket 
       -> IO Connection
accept myId peerIds listenSock = do
  sock <- fst <$> Network.Socket.accept (unSocket listenSock)
  connectSSL myId peerIds True sock

getSockAddr :: Maybe HostName -> ServiceName -> IO Network.Socket.AddrInfo
getSockAddr hn sn = do
    let hints = defaultHints { addrFlags = [AI_PASSIVE, AI_ADDRCONFIG]
                             , addrSocketType = Stream
                             }
    info <- getAddrInfo (Just hints) hn (Just sn)
    return (head info)

connectSSL :: LocalIdentity -> [PeerIdentity] -> Bool -> Network.Socket.Socket
           -> IO Connection
connectSSL myId peerIds isServer sock = do
    sslCtx <- newSSLContext myId peerIds
    conn <- connection sslCtx sock
    flip onException (shutdown conn Unidirectional) $ do
        initiate conn
        verifyConnection conn >>= flip unless (fail "Peer verification error")
        peerId <- fromX509 . fromJust =<< getPeerCertificate conn
        C conn peerId <$> getPeerName sock
  where
    verifyConnection conn = do
        verified <- getVerifyResult conn
        if not verified then return False else
            getPeerCertificate conn >>= \c -> case c of
                Nothing   -> return False
                Just cert -> do
                    let match = liftM (EQ ==) . compareX509 cert . piX509
                    anyM match peerIds
    initiate = if isServer
               then OpenSSL.Session.accept
               else OpenSSL.Session.connect

newSock :: Network.Socket.AddrInfo -> IO Network.Socket.Socket
newSock i = socket (addrFamily i) (addrSocketType i) (addrProtocol i)

newSSLContext :: LocalIdentity -> [PeerIdentity] -> IO SSLContext
newSSLContext localId validCerts = do
    ctx <- context
    contextSetPrivateKey ctx (liKey localId)
    contextSetCertificate ctx (liX509 localId)
    contextSetCiphers ctx "AES256-SHA"
    contextSetVerificationMode ctx $ VerifyPeer True False Nothing
    store <- contextGetCAStore ctx
    mapM_ (addCertToStore store . piX509) validCerts
    return ctx

anyM :: (Monad m) => (a -> m Bool) -> [a] -> m Bool
anyM _ []        = return False
anyM test (x:xs) = test x >>= \r -> if r then return True else anyM test xs
