{-# LANGUAGE DataKinds        #-}
{-# LANGUAGE QuasiQuotes      #-}
{-# LANGUAGE TemplateHaskell  #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators    #-}
module Lib
    ( startApp
    , app
    ) where

import           Auth.Biscuit
import           Auth.Biscuit.Servant
import           Data.Aeson
import           Data.Aeson.TH
import           Data.ByteString.Char8    (pack, unpack)
import           Data.List                (find)
import           Network.Wai
import           Network.Wai.Handler.Warp
import           Servant
import           System.Environment       (getEnv)

data User = User
  { userId        :: Int
  , userFirstName :: String
  , userLastName  :: String
  } deriving (Eq, Show)

$(deriveJSON defaultOptions ''User)

startApp :: IO ()
startApp = do
  -- a regular service would only need the _public_ key to check biscuits, but
  -- for convenience here we generate a biscuit when starting the app
  Just sk <- parseSecretKeyHex . pack <$> getEnv "BISCUIT_SECRET_KEY"
  let pk = toPublic sk
  b <- mkBiscuit sk [block|right("userList");|]
  putStrLn "Here's a biscuit granting access to the user list"
  print (serializeB64 b)

  -- Just pk <- parsePublicKeyHex . pack <$> getEnv "BISCUIT_PUBLIC_KEY"
  run 8080 (app pk)

type APIHandler = WithAuthorizer Handler

type API = RequireBiscuit :> ProtectedAPI

type ProtectedAPI =
  "users" :>
        ( Get '[JSON] [User]
     :<|> Capture "userId" Int :> Get '[JSON] User
        )

app :: PublicKey -> Application
app pk = serveWithContext @API Proxy (genBiscuitCtx pk) server

server :: Server API
server b =
  let handlers = userListHandler :<|> singleUserHandler
      handleAuth = handleBiscuit b
                 -- `allow if right("admin");` will be the first policy for every endpoint
                 -- policies added by endpoints (or sub-apis) will be appended
                 . withPriorityAuthorizer [authorizer|allow if right("admin");|]
                 -- `deny if true;` will be the last policy for every endpoint
                 -- policies added by endpoints (or sub-apis) will be prepended
                 -- since no matching policy makes authorization fail, `deny if true`
                 -- as the last policy is redundant
                 . withFallbackAuthorizer [authorizer|deny if true;|]
   in hoistServer @ProtectedAPI Proxy handleAuth handlers

allUsers :: [User]
allUsers = [ User 1 "Isaac" "Newton"
           , User 2 "Albert" "Einstein"
           ]

userListHandler :: APIHandler [User]
userListHandler = withAuthorizer [authorizer|allow if right("userList");|] $
  pure allUsers

singleUserHandler :: Int -> APIHandler User
singleUserHandler uid = withAuthorizer [authorizer|allow if right("getUser", ${uid});|]$
  let user = find ((== uid) . userId) allUsers
   in maybe (throwError err404) pure user
