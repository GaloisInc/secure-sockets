module Network.Secure.Identity
    (
      Identity(..)
    , PeerIdentity
    , LocalIdentity

    , toPeerIdentity
    , newLocalIdentity
      
    , piX509
    , liX509
    , liKey
    , fromX509
    ) where

import Control.Applicative ((<$>))
import Control.Exception (bracket)
import Control.Monad (when)
import Control.Monad.IO.Class (MonadIO, liftIO)
import Data.ByteString (ByteString, append, hPut)
import qualified Data.ByteString as BS
import Data.ByteString.Char8 (pack, unpack)
import Data.Maybe (fromJust, isNothing)
import OpenSSL.EVP.PKey (toKeyPair)
import OpenSSL.PEM (PemPasswordSupply(PwNone), readPrivateKey,
                    writePKCS8PrivateKey, readX509, writeX509)
import OpenSSL.RSA (RSAKeyPair)
import OpenSSL.Session (context, contextSetPrivateKey,
                        contextSetCertificate, contextCheckPrivateKey)
import OpenSSL.X509 (X509, compareX509, getSubjectName)
import System.Directory (getTemporaryDirectory, removeFile)
import System.IO (openBinaryTempFile, hFlush)
import System.IO.Unsafe (unsafePerformIO)
import System.Process(runInteractiveProcess,waitForProcess)
import System.Exit(ExitCode(..))

-- |An identity, public or private.
class Identity a where
    -- |Return the description that was associated with the identity
    -- when it was created.
    identityName :: a -> String
    -- |Serialize an identity to a 'ByteString' for storage or
    -- transmission.
    writeIdentity :: (Functor m, MonadIO m) => a -> m ByteString
    -- |Read back an identity previously serialized with
    -- writeIdentity.
    readIdentity :: (Functor m, MonadIO m) => ByteString -> m a

-- |The public identity of a peer. This kind of identity can be used
-- to authenticate the remote ends of connections.
data PeerIdentity = PI
    {
      piX509 :: X509
    , _piCN  :: String
    }

instance Eq PeerIdentity where
    a == b = compare a b == EQ

instance Ord PeerIdentity where
    compare (PI a _) (PI b _) = unsafePerformIO $ compareX509 a b

instance Show PeerIdentity where
    show (PI _ cn) = "PeerIdentity " ++ cn

instance Identity PeerIdentity where
    identityName (PI _ cn) = cn
    writeIdentity (PI cert _) = liftIO $ pack <$> writeX509 cert
    readIdentity b = do
        cert <- liftIO $ readX509 (unpack b)
        PI cert <$> getCN cert

fromX509 :: X509 -> IO PeerIdentity
fromX509 cert = PI cert <$> getCN cert

-- |A local identity. This kind of identity can be used to
-- authenticate /to/ remote ends of connections.
data LocalIdentity = LI
    {
      liX509 :: X509 
    , liKey  :: RSAKeyPair
    , _liCN  :: String
    }

instance Eq LocalIdentity where
    a == b = compare a b == EQ

instance Ord LocalIdentity where
    compare (LI c1 k1 cn1) (LI c2 k2 cn2) =
        case compare (PI c1 cn1) (PI c2 cn2) of
            EQ -> compare k1 k2
            GT -> GT
            LT -> LT

instance Show LocalIdentity where
    show (LI _ _ cn) = cn

instance Identity LocalIdentity where
    identityName (LI _ _ cn) = cn
    writeIdentity (LI cert key _) = do
        c <- liftIO $ writeX509 cert
        k <- liftIO $ writePKCS8PrivateKey key Nothing
        return $ pack (c ++ k)
    readIdentity b = do
        (PI cert cn) <- readIdentity b
        key <- liftIO $ toKeyPair <$> readPrivateKey (unpack b) PwNone
        when (isNothing key) $ fail "Bad private key"
        liftIO (certMatchesKey cert $ fromJust key) >>= \r ->
            if r
            then return $ LI cert (fromJust key) cn
            else fail "Cert and key don't match"

-- |Extract the public parts of a 'LocalIdentity' into a
-- 'PeerIdentity' suitable for sharing with peers. The resulting
-- 'PeerIdentity' will allow them to verify your identity when you
-- authenticate using the corresponding 'LocalIdentity'.
toPeerIdentity :: LocalIdentity -> PeerIdentity
toPeerIdentity (LI cert _ cn) = PI cert cn

-- |Generate a new 'LocalIdentity', giving it an identifying name and
-- a validity period in days.
--
-- Note that this function may take quite a while to execute, as it is
-- generating key material for the identity.
newLocalIdentity :: (MonadIO m) => String -> Int -> m LocalIdentity
newLocalIdentity commonName days =
    liftIO $ bracket mkKeyFile rmKeyFile $ \(p,h) -> do
        key <- run genKey
        hPut h key >> hFlush h
        cert <- run $ genCert p
        readIdentity $ append key cert
  where
    mkKeyFile = getTemporaryDirectory >>= flip openBinaryTempFile "key.pem"
    rmKeyFile = removeFile . fst
    genKey    = ("openssl", ["genrsa", "4096"])
    genCert p = ("openssl", ["req", "-batch", "-new", "-x509",
                             "-key", p, "-nodes",
                             "-subj", "/CN=" ++ commonName,
                             "-days", show days])

run :: (String,[String]) -> IO ByteString
run (x,xs) =
  do (_,o,_,h) <- runInteractiveProcess x xs Nothing Nothing
     s   <- BS.hGetContents o
     res <- waitForProcess h
     case res of
       ExitSuccess   -> return s
       ExitFailure n -> fail ("External program failed with " ++ show n)



certMatchesKey :: X509 -> RSAKeyPair -> IO Bool
certMatchesKey cert key = do
    ctx <- context
    contextSetPrivateKey ctx key
    contextSetCertificate ctx cert
    contextCheckPrivateKey ctx

getCN :: MonadIO m => X509 -> m String
getCN cert = liftIO $ fromJust . lookup "CN" <$> getSubjectName cert False
