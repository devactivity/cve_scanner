import Data.List (isInfixOf)
import System.Environment (getArgs)

data Vulnerability = CVE String | NoVuln deriving (Show)

checkVulns :: String -> [Vulnerability]
checkVulns banner = concat [
    checkApache banner,
    checkOpenSSL banner
  ]
  where
    checkApache b
      | "Apache/2.4.49" `isInfixOf` b = [CVE "CVE-2021-41773"]
      | "Apache/2.4.50" `isInfixOf` b = [CVE "CVE-2021-42013"]
      | otherwise = []
    checkOpenSSL b
      | "OpenSSL/1.0.2" `isInfixOf` b = [CVE "CVE-2016-2107"]
      | "OpenSSL/3.0.0" `isInfixOf` b = [CVE "CVE-2022-3602"]
      | otherwise = []

main :: IO ()
main = do
    args <- getArgs
    case args of
        [banner] -> print $ checkVulns banner
        _ -> putStrLn "Usage: analyzer <service_banner>"
