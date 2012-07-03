{-# LANGUAGE DeriveDataTypeable, FlexibleContexts, FlexibleInstances, FunctionalDependencies, GeneralizedNewtypeDeriving, MultiParamTypeClasses, RecordWildCards, Rank2Types, ScopedTypeVariables, TypeFamilies, UndecidableInstances #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}
{- |

This module provides a simple session implementation which stores
session data on the client as a cookie value.

The cookie values are stored in an encrypted cookie to make it more
difficult for users to tamper with the values. However, this does not
prevent replay attacks, and should not be seen as a substitute for
using HTTPS. Additionally, the cryptography libraries used to encrypt
the cookie have never been audited. Hence you are encouraged to think
carefully about what data you put in the session data.

Another important thing to realize is client-side sessions do not
provide Isolation. Imagine if the browser makes multiple simultaneous
requests, which each modify the session data. The browser will submit
the same cookie for each the requests, and each request handling
thread will get their own copy of the session data. The threads will
then modify their local copies independently and send their modified
values back to the browser, overwriting each other. The final value
will be determined by which ever request is sent last, and any changes
made by the other request will be entirely lost.

This means that clientsessions would not be suitable for implementing
a request counter, because if overlapping requests are made, the count
will be off. The count will only be accurate if the requests are
processed sequentially. That said, the demo code implements a request
counter anyway, because it is short and sweet. Also, this caveat was
forgotten when the example code was being written.

If you only modify the session data for POST requests, but not GET
requests you are less likely to run into situations where you are
losing changes, because there are not a lot of cases where a client
will be submitting multiple POST requests in parallel. Though there is
no guarantee.

Alternatively, you can choose to /only/ store data where it is OK if
modifications are lost. For example, if the session data contains only
a userid and the time of the last request they made, then there is no
great loss if some of the modifications are lost, because the access
times are going to all be about the same anyway.

By default the client will need to submit the cookie that contains the
client session data for every request (including images, and other
static assets). So, storing a large amount of data in the client
session will make requests slower and is not recommended. If you have
assets which can be served with out examining the client session data
you can use the 'sessionPath' and 'sessionDomain' parameters of
'SessionConf' to limit when the browser sends the session data cookie.

The first thing you need to do is enable some extensions which can be
done via a @LANGUAGE@ pragma at the top of your app:

 {\-\# LANGUAGE DeriveDataTypeable, TemplateHaskell #\-\}

Then you will need some imports:

> module Main where
>
> import Happstack.Server   (ServerPartT, Response, simpleHTTP
>                          , nullConf, nullDir, ok, toResponse
>                          )
> import Happstack.Server.ClientSession
>                           ( ClientSession(..), ClientSessionT(..)
>                          , getDefaultKey, mkSessionConf
>                          , liftSessionStateT, withClientSessionT
>                          )
> import Data.Data          (Data, Typeable)
> import Data.Lens          ((+=))
> import Data.Lens.Template (makeLens)
> import Data.SafeCopy      (base, deriveSafeCopy)

Next you will want to create a type to hold your session data. Here we
use a simple record which we will update using @data-lens-fd@. But,
you could also store a, @Map Text Text@, or whatever suits your fancy
as long as it can be serialized. (So no data types that include
functions, existential types, etc).

> data SessionData = SessionData
>     { _count    :: Integer
>     }
>    deriving (Eq, Ord, Read, Show, Data, Typeable)
>
> -- | here we make it a lens, but that is not required
> $(makeLens ''SessionData)

We use the @safecopy@ library to serialize the data so we can encrypt
it and store it in a cookie. @safecopy@ provides version migration,
which means that we will be able to read-in old session data if we
change the data type. The easiest way to create a 'SafeCopy' instance
is with 'deriveSafeCopy':

> $(deriveSafeCopy 0 'base ''SessionData)

We also need to define what an 'emptySession' looks like. This will be
used for creating new sessions when the client does not already have
one:

> instance ClientSession SessionData where
>     emptySession = SessionData { _count = 0 }

Next we have a function which reads a client-specific page counter and returns
the number of times the page has been reloaded.

In this function we use, 'liftSessionStateT' to lift the '+=' lens
function into 'ClientSessionT' to increment and return the value
stored in the client session.

Alternatively, we could have used the 'getSession' and 'putSession'
functions from 'MonadClientSession'. Those functions do not require
the use of 'liftSessionStateT'.

> routes :: ClientSessionT SessionData (ServerPartT IO) Response
> routes =
>     do nullDir
>        c <- liftSessionStateT $ count += 1
>        ok $ toResponse $ "you have viewed this page " ++ (show c) ++ " time(s)."

Finally, we unwrap the 'ClientSessionT' monad transformer using 'withClientSessionT'.

The 'SessionConf' type requires an encryption key. You can generate
the key using 'getDefaultKey' uses a default filename. Alternatively,
you can specific the name you want to use explicitly using
'getKey'. The key will be created automatically if it does not already
exist.

If you change the key, all existing client sessions will be invalidated.

> main :: IO ()
> main =
>     do key <- getDefaultKey
>        let sessionConf = mkSessionConf key
>        simpleHTTP nullConf $ withClientSessionT sessionConf $ routes

In a real application you might want to use a @newtype@ wrapper around
'ClientSessionT' to keep your type signatures sane. An alternative
version of this demo which does that can be found here:

<http://patch-tag.com/r/mae/happstack/snapshot/current/content/pretty/happstack-clientsession/demo/demo.hs>

-}
module Happstack.Server.ClientSession
  ( -- * Happstack.Server.ClientSession
    ClientSession(..)
  , SessionStatus(..)
  , MonadClientSession(getSession, putSession, expireSession)
  , SessionConf(..)
  , mkSessionConf
  , ClientSessionT(..)
  , mapClientSessionT
  , runClientSessionT
  , withClientSessionT
  , SessionStateT
  , mapSessionStateT
  , liftSessionStateT
    -- * Exported from @Web.ClientSession@
  , Key
  , getKey
  , getDefaultKey
  , randomKey
  ) where

import Control.Applicative   (Applicative, Alternative, optional)
import Control.Monad         (MonadPlus(..), liftM)
import Control.Monad.Base    (MonadBase )
import Control.Monad.Cont    (MonadCont)
import Control.Monad.Error   (MonadError)
import Control.Monad.Fix     (MonadFix)
import Control.Monad.Reader  (MonadReader(ask, local), ReaderT(..), mapReaderT)
import Control.Monad.State   (MonadState(get,put), StateT(..), mapStateT)
import Control.Monad.Writer  (MonadWriter(tell, listen, pass))
import Control.Monad.RWS     (MonadRWS)
import Control.Monad.Trans   (MonadIO(liftIO), MonadTrans(lift))
import Control.Monad.Trans.Control               ( MonadTransControl(..)
                                                 , MonadBaseControl(..)
                                                 , ComposeSt, defaultLiftBaseWith, defaultRestoreM
                                                 )
import Data.ByteString.Char8 (pack, unpack)
import Data.Monoid           (Monoid(..))
import Data.SafeCopy         (SafeCopy(getCopy, putCopy), contain, safeGet, safePut)
import Data.Serialize        (runGet, runPut)
import Happstack.Server      ( HasRqData, FilterMonad, WebMonad, ServerMonad, Happstack, Response
                             , CookieLife(Session), Cookie(secure,cookiePath, cookieDomain, httpOnly)
                             , lookCookieValue, addCookie, mkCookie, expireCookie
                             )
import Web.ClientSession     (Key, getKey, getDefaultKey, randomKey, decrypt, encryptIO)

import qualified Data.Serialize as S

instance SafeCopy Key where
    getCopy = contain $ S.get
    putCopy = contain . S.put

------------------------------------------------------------------------------
-- class ClientSession
------------------------------------------------------------------------------

-- | Your session type must have an instance for this class.
class SafeCopy st => ClientSession st where
  -- | An empty session, i.e. what you get when there is no existing
  -- session stored.
  emptySession :: st

------------------------------------------------------------------------------
-- SessionConf
------------------------------------------------------------------------------

-- | Configuration for the session cookie for passing to 'runClientSessionT' or 'withClientSessionT'.
data SessionConf = SessionConf
    { sessionCookieName :: String      -- ^ Name of the cookie to hold your session data.
    , sessionCookieLife :: CookieLife  -- ^ Lifetime of that cookie.
    , sessionKey        :: Key         -- ^ Encryption key, usually from one of 'getKey', 'getDefaultKey' and 'randomKey'.
    , sessionDomain     :: String      -- ^ cookie domain
    , sessionPath       :: String      -- ^ cookie path
    , sessionSecure     :: Bool        -- ^ Only use a session over secure transports.
    , sessionHttpOnly   :: Bool        -- ^ Only use session over HTTP (to prevent it from being stolen via cross-site scripting)
    }

-- | Create a 'SessionConf' using defaults for everything except
-- 'sessionKey'.  You can use record update syntax to override individual
-- fields.
--
-- > main = do key <- getDefaultKey
-- >           let sessConf = (mkSessionConf key) { sessionCookieLife = oneWeek }
-- >           simpleHTTP nullConf $ withClientSessionT sessConf handlers
-- >   where
-- >     oneWeek  = MaxAge $ 60 * 60 * 24 * 7
-- >     handlers = msum [...]
--
-- 'mkSessionConf' is currently defined as:
--
-- > mkSessionConf :: Key -> SessionConf
-- > mkSessionConf key = SessionConf
-- >    { sessionCookieName = "Happstack.ClientSession"
-- >    , sessionCookieLife = Session
-- >    , sessionKey        = key
-- >    , sessionDomain     = ""
-- >    , sessionPath       = "/"
-- >    , sessionSecure     = False
-- >    , sessionHttpOnly   = True
-- >    }
--
-- see also: 'getKey', 'getDefaultKey'
mkSessionConf :: Key -> SessionConf
mkSessionConf key = SessionConf
    { sessionCookieName = "Happstack.ClientSession"
    , sessionCookieLife = Session
    , sessionKey        = key
    , sessionDomain     = ""
    , sessionPath       = "/"
    , sessionSecure     = False
    , sessionHttpOnly   = True
    }

------------------------------------------------------------------------------
-- SessionStateT
------------------------------------------------------------------------------

-- | Wrapper around the sessionData which tracks it state so we can
-- avoid decoding or encoding/sending the cookie when not required
data SessionStatus sessionData = Unread | NoChange sessionData | Modified sessionData  | Expired
      deriving (Eq, Ord, Read, Show)

-- | 'SessionStateT' is like 'StateT', except it records if 'put' was ever called
newtype SessionStateT s m a = SessionStateT { unSessionStateT :: StateT (SessionStatus s) m a }
    deriving ( Functor, Applicative, Alternative, Monad, MonadPlus, MonadBase b, MonadIO, MonadFix, MonadError e, MonadCont
             , MonadTrans, HasRqData, FilterMonad r, WebMonad r, ServerMonad)

instance Happstack m => Happstack (SessionStateT sessionData m)

instance (MonadPlus m) => Monoid (SessionStateT sessionData m a) where
    mempty  = mzero
    mappend = mplus

instance (Monad m, ClientSession sessionData) => MonadState sessionData (SessionStateT sessionData m)  where
    get   = SessionStateT $ do sd <- get
                               case sd of
                                 (NoChange sd') -> return sd'
                                 (Modified sd') -> return sd'
                                 _              -> return emptySession
    put a = SessionStateT $ put (Modified a)

instance MonadTransControl (SessionStateT s) where
    newtype StT (SessionStateT s) a = StSessionStateT { unStSessionStateT :: StT (StateT (SessionStatus s)) a }
    liftWith f =
        SessionStateT $ liftWith $ \runStateT' ->
            f $ liftM StSessionStateT . runStateT' . unSessionStateT
    restoreT = SessionStateT . restoreT . liftM unStSessionStateT

instance MonadBaseControl b m => MonadBaseControl b (SessionStateT s m) where
    newtype StM (SessionStateT s m) a = StMSessionStateT { unStMSessionStateT :: ComposeSt (SessionStateT s) m a }
    liftBaseWith = defaultLiftBaseWith StMSessionStateT
    restoreM     = defaultRestoreM     unStMSessionStateT

-- | run 'SessionStateT' and get the result, plus the final @SessionStatus sessionData@
runSessionStateT :: SessionStateT sessionData m a -> SessionStatus sessionData -> m (a, SessionStatus sessionData)
runSessionStateT = runStateT . unSessionStateT

-- | Transform the inner monad. (similar to 'mapStateT')
--
-- The @forall s.@ is to prevent you from modifying the session state.
--
-- In theory we want this function to have the type:
--
-- > mapSessionStateT :: (m a -> n b) -> SessionStateT s m a -> SessionStateT s n b
--
-- But that can not be done, so this is the next best thing.
--
mapSessionStateT :: (forall s. m (a, s) -> n (b, s))
                 -> SessionStateT sessionData m a
                 -> SessionStateT sessionData n b
mapSessionStateT f (SessionStateT m) =
    SessionStateT $ mapStateT f m

-- | similar to 'mapStateT'. This version allows modification of the session data
mapSessionStateT_ :: (m (a, SessionStatus s) -> n (b, SessionStatus s))
                 -> SessionStateT s m a
                 -> SessionStateT s n b
mapSessionStateT_ f (SessionStateT m) = SessionStateT $ mapStateT f m

------------------------------------------------------------------------------
-- ClientSessionT
------------------------------------------------------------------------------

-- | 'ClientSessionT' provides an environment in which we can access and update the client-side session state
--
-- The inner monad needs to provide an instance of 'Happstack' so that
-- the cookie value can be read and set. According 'ClientSessionT'
-- must appear outside 'ServerPartT' not inside it.
newtype ClientSessionT sessionData m a = ClientSessionT { unClientSessionT :: ReaderT SessionConf (SessionStateT sessionData m) a }
    deriving ( Functor, Applicative, Alternative, Monad, MonadBase b, MonadPlus, MonadIO, MonadFix, MonadError e, MonadCont
             , HasRqData, FilterMonad r, WebMonad r, ServerMonad)

-- | run the 'ClientSessionT' monad and get the result plus the final @SessionStatus sessionData@
--
-- This function does /not/ automatically update the cookie if the
-- session has been modified. It is up to you to do that. You probably
-- want to use 'withClientSessionT' instead.
--
-- see also: 'withClientSessionT', 'mkSessionConf'
runClientSessionT :: ClientSessionT sessionData m a -> SessionConf -> m (a, SessionStatus sessionData)
runClientSessionT cs sc = runSessionStateT (runReaderT (unClientSessionT cs) sc) Unread

instance Happstack m => Happstack (ClientSessionT sessionData m)

instance (MonadPlus m) => Monoid (ClientSessionT sessionData m a) where
    mempty  = mzero
    mappend = mplus

instance MonadTrans (ClientSessionT sessionData) where
    lift = ClientSessionT . lift . lift

instance MonadTransControl (ClientSessionT s) where
    newtype StT (ClientSessionT s) a = StClientSessionT { unStClientSessionT :: StT (SessionStateT s) (StT (ReaderT SessionConf) a) }

    liftWith f =
        ClientSessionT $ liftWith $ \runSessionStateT' ->
            liftWith $ \runReaderT' ->
            f $ liftM StClientSessionT . runReaderT' . runSessionStateT' . unClientSessionT

    restoreT = ClientSessionT . restoreT . restoreT . liftM unStClientSessionT

instance MonadBaseControl b m => MonadBaseControl b (ClientSessionT s m) where
    newtype StM (ClientSessionT s m) a = StMClientSessionT { unStMClientSessionT :: ComposeSt (ClientSessionT s) m a }
    liftBaseWith = defaultLiftBaseWith StMClientSessionT
    restoreM     = defaultRestoreM     unStMClientSessionT

-- | transform the inner monad, but leave the session data alone.
mapClientSessionT :: (forall s. m (a, s) -> n (b, s))
                  -> ClientSessionT sessionData m a
                  -> ClientSessionT sessionData n b
mapClientSessionT f (ClientSessionT m) = ClientSessionT $ mapReaderT (mapSessionStateT f) m

-- | transform the inner monad
mapClientSessionT_ :: (m (a, SessionStatus sessionData) -> n (b, SessionStatus sessionData))
                  -> ClientSessionT sessionData m a
                  -> ClientSessionT sessionData n b
mapClientSessionT_ f (ClientSessionT m) = ClientSessionT $ mapReaderT (mapSessionStateT_ f) m

instance (MonadReader r m) => MonadReader r (ClientSessionT sessionData m) where
    ask = lift ask
    local = mapClientSessionT_ . local

instance (MonadWriter w m) => MonadWriter w (ClientSessionT sessionData m) where
    tell     = lift . tell

    listen = mapClientSessionT listen'
        where
          listen' :: m (a, s) -> m ((a, w), s)
          listen' m =
              do ((a, s), w') <- listen m
                 return ((a, w'), s)
    pass = mapClientSessionT pass'
        where
          pass' :: m ((a, w -> w), s) -> m (a, s)
          pass' m =
              do ((a, f), st) <- m
                 a' <- pass $ return (a, f)
                 return (a', st)

instance (MonadState s m) => MonadState s (ClientSessionT sessionData m) where
    get   = lift get
    put a = lift (put a)

instance (MonadRWS r w s m) => MonadRWS r w s (ClientSessionT sessionData m)

------------------------------------------------------------------------------
-- Internals
------------------------------------------------------------------------------

-- | Fetch the 'SessionConf'
askSessionConf :: (Monad m) => ClientSessionT sessionData m SessionConf
askSessionConf = ClientSessionT ask

-- | Fetch the 'SessionConf' and apply a function to it
asksSessionConf :: (Monad m) => (SessionConf -> a) -> ClientSessionT sessionData m a
asksSessionConf f = do
    sc <- askSessionConf
    return (f sc)

-- | Fetch the current value of the state within the monad.
getSessionStatus :: (Monad m) => ClientSessionT sessionData m (SessionStatus sessionData)
getSessionStatus =
    ClientSessionT $ ReaderT $ \_ -> SessionStateT get

-- | @'put' s@ sets the state within the monad to @s@.
putSessionStatus :: Monad m => SessionStatus sessionData -> ClientSessionT sessionData m ()
putSessionStatus sd =
    ClientSessionT $ ReaderT $ \_ -> SessionStateT $ put sd

-- | create a new session by calling 'emptySession'
newSession :: (Monad m, ClientSession st) => m st
newSession = return emptySession

-- | decode the encypted cookie string
decode :: (Monad m, ClientSession sessionData) =>
          String
       -> ClientSessionT sessionData m sessionData
decode v = do key <- asksSessionConf sessionKey
              maybe newSession (either (const newSession) return . runGet safeGet)
                     . decrypt key $ pack v

-- | get the session cookie and decrypt it. If no cookie is found, return a new 'emptySession'.
getValue :: (Functor m, Monad m, MonadPlus m, HasRqData m, ClientSession sessionData) =>
            ClientSessionT sessionData m sessionData
getValue = do name <- asksSessionConf sessionCookieName
              value <- optional $ lookCookieValue name
              maybe newSession decode value

-- | get the @sessionData@
getSessionCST :: (Functor m, MonadPlus m, HasRqData m, ClientSession sessionData)
           => ClientSessionT sessionData m sessionData
getSessionCST =
    do sd <- getSessionStatus
       case sd of
         Unread ->
             do a <- getValue
                putSessionStatus (NoChange a)
                return a
         NoChange a  ->
             return a
         Modified a ->
             return a
         Expired ->
             newSession

-- | Put a new value in the session.
putSessionCST :: (Monad m, ClientSession sessionData) => sessionData -> ClientSessionT sessionData m ()
putSessionCST sd = putSessionStatus (Modified sd)

-- | Expire the session, i.e. the cookie holding it.
expireSessionCST :: Monad m => ClientSessionT st m ()
expireSessionCST = putSessionStatus Expired

------------------------------------------------------------------------------
-- MonadClientSession
------------------------------------------------------------------------------

-- | 'MonadClientSession' provides the primary interface to get @sessionData@, put @sessionData@ or expire @sessionData@.
--
-- This is a class so you can use newtype deriving to make the functions available in your custom server monad.
class MonadClientSession sessionData m | m -> sessionData where
    getSession    :: m sessionData         -- ^ get the current @sessionData@
    putSession    :: sessionData -> m ()   -- ^ set the @sessionData@
    expireSession :: m ()                  -- ^ expire the session (deletes the cookie)

instance (Functor m , MonadPlus m, HasRqData m, ClientSession sessionData) =>
    (MonadClientSession sessionData (ClientSessionT sessionData m)) where
    getSession    = getSessionCST
    putSession    = putSessionCST
    expireSession = expireSessionCST

------------------------------------------------------------------------------
-- liftSessionStateT
------------------------------------------------------------------------------

-- | lift a computation from the 'SessionStateT' monad
--
-- The primary purpose of this function is to make it possible to use
-- the 'MonadState' functions such as 'get' and 'set' to get and set
-- the current session data.
--
-- That makes it possible to use the 'MonadState' based functions provided by 'Data.Lens', e.g.:
--
-- > do c <- liftSessionStateT $ count += 1
--
liftSessionStateT :: (Monad m, MonadTrans t, MonadClientSession sessionData (t m), Monad (t m)) =>
                     SessionStateT sessionData m a
                  -> t m a
liftSessionStateT m =
    do sd <- getSession
       (a, sd') <- lift $ runSessionStateT m (NoChange sd)
       case sd' of
         (Modified sd'') -> putSession sd''
         (NoChange _   ) -> return ()
         Unread          -> error "liftSessionStateT: session data came back Unread. How did that happen?"
         Expired         -> error "liftSessionStateT: session data came back Expired. How did that happen?"
       return a

------------------------------------------------------------------------------
-- withClientSessionT
------------------------------------------------------------------------------

-- | Wrapper around your handlers that use the session.
--
-- This function automatically takes care of expiring or updating the
-- cookie if the 'expireSession' or 'modifySession' is called.
--
-- If no changes are made to the session, then the cookie will not be
-- resent (because there is no need to).
withClientSessionT :: (Happstack m, Functor m, Monad m, FilterMonad Response m, ClientSession sessionData) =>
                      SessionConf
                   -> ClientSessionT sessionData m a
                   -> m a
withClientSessionT sessionConf@SessionConf{..} part =
  do (a, sd) <- runClientSessionT part sessionConf
     case sd of
      Modified sd' -> encode sd'
      Expired      -> expire
      _            -> return ()
     return a
  where
    encode sd = do bytes <- liftIO . encryptIO sessionKey . runPut . safePut $ sd
                   let cookie = (mkCookie sessionCookieName $ unpack bytes) { cookieDomain = sessionDomain
                                                                            , cookiePath   = sessionPath
                                                                            , secure       = sessionSecure
                                                                            , httpOnly     = sessionHttpOnly
                                                                            }
                   addCookie sessionCookieLife cookie
    expire = expireCookie sessionCookieName
