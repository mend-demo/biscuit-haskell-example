{-# LANGUAGE DataKinds       #-}
{-# LANGUAGE QuasiQuotes     #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TypeOperators   #-}
module Lib
    ( startApp
    , app
    ) where

import           Auth.Biscuit
import           Data.Aeson
import           Data.Aeson.TH
import           Data.ByteString.Char8    (pack, unpack)
import           Network.Wai
import           Network.Wai.Handler.Warp
import           Servant
import           System.Environment       (getEnv)

import           Biscuit

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
  Just privateKey <- parsePrivateKeyHex . pack <$> getEnv "BISCUIT_PRIVATE_KEY"
  kp <- fromPrivateKey privateKey
  b <- mkBiscuit kp [block|right(#authority,#userList);|]
  putStrLn "Here's a biscuit granting access to the user list"
  print (serializeHex b)

  let pk = publicKey kp
  -- Just pk <- parsePublicKeyHex . pack <$> getEnv "BISCUIT_PUBLIC_KEY"
  run 8080 (app pk)

type API = RequireBiscuit :> "users" :> Get '[JSON] [User]

app :: PublicKey -> Application
app pk = serveWithContext api (genBiscuitCtx pk) server

api :: Proxy API
api = Proxy

server :: Server API
server b = checkBiscuit b [verifier|allow if right(#authority, #userList);|] $
  pure [ User 1 "Isaac" "Newton"
       , User 2 "Albert" "Einstein"
       ]
