-- |This library simplifies the task of securely connecting two
-- servers to each other. It closely mimicks the regular socket API,
-- and adds the concept of identity: each communicating server has an
-- identity, and connections can only be established between two
-- servers who know each other and expect to be communicating.
--
-- Under the hood, the library takes care of strongly authenticating
-- the connection, and of encrypting all traffic. If you successfully
-- establish a connection using this library, you have the guarantee
-- that the connection is secure.

{-# LANGUAGE NoImplicitPrelude #-}

module Network.Secure
    (
      -- * Tutorial
      -- $tutorial

      -- * Internals and caveats
      -- $internals

      -- * Managing identities
      Identity(..)
    , PeerIdentity
    , LocalIdentity

    , toPeerIdentity
    , newLocalIdentity

      -- * Communicating

      -- ** Connecting to peers
    , connect

      -- ** Accepting connections from peers
    , Socket
    , newServer
    , accept

      -- ** Talking to connected peers
    , Connection
    , peer  
    , read
    , readPtr
    , write
    , writePtr
    , close

      -- ** Misc reexports from 'Network.Socket'
    , HostName
    , ServiceName
    ) where

import Network.Secure.Connection
import Network.Secure.Identity

-- $tutorial
--
-- First, each host needs to generate a local identity for itself. A
-- local identity allows a server to authenticate itself to remote
-- peers.
--
-- > do
-- >   id <- newLocalIdentity "server1.domain.com" 365
-- >   writeIdentity id >>= writeFile "server.key"
--
-- The name is not used at all by the library, it just allows you to
-- identify the key later on if you need to.
--
-- This identity contains secret key material that only the generating
-- host should have. From this, we need to generate a public identity
-- that can be given to other hosts.
--
-- > do
-- >   id <- readFile "server.key" >>= readIdentity
-- >   writeIdentity (toPeerIdentity id) >>= writeFile "server.pub"
--
-- This public file should be distributed to the servers with whom you
-- want to communicate. Once everyone has the public identities of
-- their peers, we can start connecting. First, one host needs to
-- start listening for connections.
--
-- > do
-- >   me     <- readFile "a.key" >>= readIdentity
-- >   you    <- readFile "b.pub" >>= readIdentity
-- >   server <- newServer (Nothing, "4242")
-- >   conn   <- accept me [you] server
--
-- Then, another host needs to connect.
--
-- > do
-- >   me   <- readFile "b.key" >>= readIdentity
-- >   you  <- readFile "a.pub" >>= readIdentity
-- >   conn <- connect me you ("a.com", "4242")
--
-- Et voila! From there on, you can communicate using the usual
-- socket-ish API:
--
-- > do
-- >   write conn "hello?"
-- >   read conn >>= putStrLn
-- >   close conn

-- $internals
--
-- Note that this section gives out internal implementation details
-- which are subject to change! Compatibility breakages will be
-- indicated by appropriate version number bumps for the package, and
-- the internal details of new versions may bear no resemblance
-- whatsoever to the old version.
--
-- The current implementation uses OpenSSL (via HsOpenSSL) for
-- transport security, with the @AES256-SHA@ ciphersuite and 4096 bit
-- RSA keys.
--
-- Due to a current limitation of the HsOpenSSL API, we do not use a
-- ciphersuite that makes use of ephemeral keys for encryption. The
-- consequence is that connections established with this library do
-- not provide perfect forward secrecy.
--
-- That is, if an attacker can compromise the private keys of the
-- communicating servers, she can decrypt all past communications that
-- she has recorded.
--
-- This shortcoming will be fixed at some point, either by adding
-- Diffie-Hellman keying support to HsOpenSSL, or by switching to a
-- different underlying implementation.
