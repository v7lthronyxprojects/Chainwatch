import os
import json
import asyncio
import aiohttp
import pandas as pd
from collections import Counter
from typing import List, Dict, Any, Set, Optional
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump
from termcolor import colored
import matplotlib.pyplot as plt
import time
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import QSizePolicy
from aiohttp import ClientTimeout
from ratelimit import limits, sleep_and_retry
from utils.file_utils import load_json_file, save_json_file

load_dotenv()

LANGUAGE = os.getenv("LANGUAGE", "en").lower() 

def translate(text_fa: str, text_en: str, language: str = None) -> str:
    if language is None:
        language = os.getenv("LANGUAGE", "en").lower()
    return text_fa if language == 'fa' else text_en

CONFIG = {
    "Tron": {
        "api_key": os.getenv("TRON_API_KEY"),
        "base_url": os.getenv("TRON_BASE_URL"),
        "threshold": int(os.getenv("TRON_THRESHOLD", 5000000)),
        "unit": os.getenv("TRON_UNIT", "SUN")
    },
    "Ethereum": {
        "etherscan_api_key": os.getenv("ETHERSCAN_API_KEY"),
        "blockcypher_token": os.getenv("BLOCKCYPHER_TOKEN"),
        "base_url_blockcypher": os.getenv("ETH_BASE_URL_BLOCKCYPHER"),
        "threshold": int(os.getenv("ETH_THRESHOLD", 10)),
        "unit": os.getenv("ETH_UNIT", "ETH")
    },
    "BSC": {
        "bscscan_api_key": os.getenv("BSCSCAN_API_KEY"),
        "base_url": os.getenv("BSC_BASE_URL"),
        "threshold": int(os.getenv("BSC_THRESHOLD", 100)),
        "unit": os.getenv("BSC_UNIT", "BNB")
    },
    "Solana": {
        "quicknode_url": os.getenv("QUICKNODE_URL"),
        "wss_url": os.getenv("QUICKNODE_WSS_URL"),
        "threshold": int(os.getenv("SOLANA_THRESHOLD", 1000)),
        "unit": os.getenv("SOLANA_UNIT", "SOL")
    },
    "Linea": {
        "infura_url": os.getenv("LINEA_INFURA_URL")
    },
    "Moralis": {
        "api_key": os.getenv("MORALIS_API_KEY")
    },
    "Polygon": {
        "polygonscan_api_key": os.getenv("POLYGONSCAN_API_KEY"),
        "base_url": os.getenv("POLYGON_BASE_URL", "https://api.polygonscan.com/api"),
        "threshold": int(os.getenv("POLYGON_THRESHOLD", 1000)),
        "unit": os.getenv("POLYGON_UNIT", "MATIC")
    },
    "Avalanche": {
        "snowtrace_api_key": os.getenv("SNOWTRACE_API_KEY"),
        "base_url": os.getenv("AVAX_BASE_URL", "https://api.snowtrace.io/api"),
        "threshold": int(os.getenv("AVAX_THRESHOLD", 100)),
        "unit": os.getenv("AVAX_UNIT", "AVAX")
    },
    "Fantom": {
        "ftmscan_api_key": os.getenv("FTMSCAN_API_KEY"),
        "base_url": os.getenv("FTM_BASE_URL", "https://api.ftmscan.com/api"),
        "threshold": int(os.getenv("FTM_THRESHOLD", 1000)),
        "unit": os.getenv("FTM_UNIT", "FTM")
    },
    "Arbitrum": {
        "arbiscan_api_key": os.getenv("ARBISCAN_API_KEY"),
        "base_url": os.getenv("ARB_BASE_URL", "https://api.arbiscan.io/api"),
        "threshold": int(os.getenv("ARB_THRESHOLD", 100)),
        "unit": os.getenv("ARB_UNIT", "ARB")
    },
    "Optimism": {
        "optimistic_api_key": os.getenv("OPTIMISTIC_API_KEY"),
        "base_url": os.getenv("OP_BASE_URL", "https://api-optimistic.etherscan.io/api"),
        "threshold": int(os.getenv("OP_THRESHOLD", 100)),
        "unit": os.getenv("OP_UNIT", "OP")
    }
}

BLACKLIST_FILE = 'data/blacklist_addresses.json'
KNOWN_EXCHANGES_FILE = 'data/known_exchanges.json'
FRAUD_PROBABILITY_THRESHOLD = 50
MAX_DEPTH = 3

class ChainWatchAnalyzer:
    def __init__(self, log_callback=None, language="en"):
        self.known_exchanges = load_json_file(KNOWN_EXCHANGES_FILE, {
            "Tron": [], "Ethereum": [], "BSC": [], "Solana": [], "Linea": []
        })
        self.blacklist_addresses = set(load_json_file(BLACKLIST_FILE, []))
        self.parsers = {
            'Tron': self._parse_tron_tx,
            'Ethereum': self._parse_eth_tx,
            'BSC': self._parse_bsc_tx,
            'Solana': self._parse_solana_tx,
            'Linea': self._parse_linea_tx
        }
        self.log_callback = log_callback
        self.timeout = ClientTimeout(total=60)
        self.api_calls = {}
        self.language = language
        self.translate = lambda fa, en: translate(fa, en, self.language)
        self.sleep_func = asyncio.sleep

    def set_language(self, language: str):
        self.language = language

    def log(self, message: str, color: str = "cyan"):
        if self.log_callback:
            self.log_callback(message, color)
        else:
            print(colored(message, color))

    def _parse_tron_tx(self, tx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not tx or not isinstance(tx, dict):
            return None

        try:
            parsed = {
                "hash": tx.get("hash"),
                "timestamp": pd.to_datetime(tx.get("timestamp"), unit="ms"),
                "ownerAddress": tx.get("ownerAddress"),
                "toAddress": tx.get("toAddress", tx.get("toAddressList", [""])[0]),
                "amount": 0
            }

            if tx.get("contractType") == 1:
                amount = tx.get("amount", "0")
                parsed["amount"] = float(amount) / 1_000_000
            elif tx.get("contractType") == 2:
                contract_data = tx.get("contractData", {})
                amount = contract_data.get("amount", "0")
                parsed["amount"] = float(amount) / 1_000_000
            elif tx.get("contractType") == 31:
                trigger_info = tx.get("trigger_info", {})
                if trigger_info.get("methodName") == "transfer":
                    value = trigger_info.get("parameter", {}).get("_value", "0")
                    parsed["amount"] = float(value) / 1_000_000

            return parsed
        except Exception as e:
            self.log(self.translate(
                f"Error parsing Tron transaction: {str(e)}",
                f"Error parsing Tron transaction: {str(e)}"
            ), "red")
            return None

    def _parse_eth_tx(self, tx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not tx:
            return None
        return {
            "hash": tx.get("hash"),
            "timestamp": pd.to_datetime(tx.get("timeStamp"), unit='s'),
            "ownerAddress": tx.get("from"),
            "toAddress": tx.get("to"),
            "amount": float(tx.get("value", 0)) / 1e18
        }

    def _parse_bsc_tx(self, tx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not tx:
            return None
        return {
            "hash": tx.get("hash"),
            "timestamp": pd.to_datetime(tx.get("timeStamp"), unit='s'),
            "ownerAddress": tx.get("from"),
            "toAddress": tx.get("to"),
            "amount": float(tx.get("value", 0)) / 1e18
        }

    def _parse_solana_tx(self, tx: Dict[str, Any], block_time: Any) -> Optional[Dict[str, Any]]:
        if not tx:
            return None
        return {
            "hash": tx.get("signature"),
            "timestamp": pd.to_datetime(block_time, unit='s') if block_time else pd.NaT,
            "ownerAddress": tx.get("memo", "Unknown"),
            "toAddress": "Unknown",
            "amount": 0
        }

    def _parse_linea_tx(self, tx: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if not tx:
            return None
        return {
            "hash": tx.get("hash"),
            "timestamp": pd.to_datetime(tx.get("timestamp"), unit='s'),
            "ownerAddress": tx.get("from"),
            "toAddress": tx.get("to"),
            "amount": float(tx.get("value", 0)) / 1e18
        }

    async def fetch_solana_block_time(self, session: aiohttp.ClientSession, slot: int) -> Any:
        url = CONFIG['Solana']['quicknode_url']
        headers = {
            "Content-Type": "application/json"
        }
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBlockTime",
            "params": [slot]
        }
        try:
            async with session.post(url, headers=headers, json=payload) as response:
                response.raise_for_status()
                data = await response.json()
                return data.get("result")
        except aiohttp.ClientError as e:
            self.log(self.translate(
                f"Error fetching block time for slot {slot}: {e}",
                f"Error fetching block time for slot {slot}: {e}"
            ), "red")
            return None

    def detect_blockchain_from_address(self, address: str) -> str:
        """Enhanced blockchain detection with more chains"""
        if not address:
            return 'Unknown'
        
        patterns = {
            'Ethereum': lambda x: x.startswith('0x') and len(x) == 42,
            'Tron': lambda x: x.startswith('T') and len(x) == 34,
            'Solana': lambda x: 32 <= len(x) <= 44 and not x.startswith('0x') and not x.startswith('T'),
            'Linea': lambda x: x.startswith('0x') and len(x) == 66,
            'Polygon': lambda x: x.startswith('0x') and len(x) == 42,
            'Avalanche': lambda x: x.startswith('0x') and len(x) == 42,
            'Fantom': lambda x: x.startswith('0x') and len(x) == 42,
            'Arbitrum': lambda x: x.startswith('0x') and len(x) == 42,
            'Optimism': lambda x: x.startswith('0x') and len(x) == 42
        }
        
        for chain, pattern in patterns.items():
            if pattern(address):
                if chain in ['Polygon', 'Avalanche', 'Fantom', 'Arbitrum', 'Optimism']:
                    pass
                return chain
        
        return 'Unknown'

    def validate_addresses(self, addresses: List[str]) -> Dict[str, List[str]]:
        if not addresses:
            return {chain: [] for chain in CONFIG.keys()}

        validated = {chain: [] for chain in CONFIG.keys()}

        for addr in addresses:
            if not isinstance(addr, str) or len(addr) < 26:
                self.log(self.translate(
                    f"Invalid address format: {addr}",
                    f"Invalid address format: {addr}"
                ), "red")
                continue

            blockchain = self.detect_blockchain_from_address(addr)
            if blockchain != 'Unknown':
                validated[blockchain].append(addr.strip())
            else:
                self.log(self.translate(
                    f"Blockchain type for address {addr} could not be determined.",
                    f"Blockchain type for address {addr} could not be determined."
                ), "yellow")

        return validated

    async def fetch_transactions_solana(self, session: aiohttp.ClientSession, wallet_address: str) -> List[Dict[str, Any]]:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getConfirmedSignaturesForAddress2",
            "params": [wallet_address, {"limit": 50}]
        }
        try:
            async with session.post(CONFIG['Solana']['quicknode_url'], json=payload) as response:
                response.raise_for_status()
                data = await response.json()
                return data.get("result", [])
        except aiohttp.ClientError as e:
            self.log(self.translate(
                f"Error fetching Solana transactions for {wallet_address}: {e}",
                f"Error fetching Solana transactions for {wallet_address}: {e}"
            ), "red")
            return []

    async def fetch_transactions_linea(self, session: aiohttp.ClientSession, wallet_address: str) -> List[Dict[str, Any]]:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getTransactionByHash",
            "params": [wallet_address]
        }
        try:
            async with session.post(CONFIG['Linea']['infura_url'], json=payload) as response:
                response.raise_for_status()
                data = await response.json()
                return [data.get("result", {})] if data.get("result") else []
        except aiohttp.ClientError as e:
            self.log(self.translate(
                f"Error fetching Linea transactions for {wallet_address}: {e}",
                f"Error fetching Linea transactions for {wallet_address}: {e}"
            ), "red")
            return []

    @sleep_and_retry
    @limits(calls=5, period=1)
    async def fetch_transactions(self, wallet_address: str, blockchain: str) -> List[Dict[str, Any]]:
        """Enhanced fetch_transactions with better error handling"""
        if not wallet_address or not blockchain:
            raise ValueError(self.translate(
                "Wallet address and blockchain must be specified",
                "Wallet address and blockchain must be specified"
            ))

        timeout = aiohttp.ClientTimeout(total=30)
        max_retries = 3
        retry_delay = 1

        for attempt in range(max_retries):
            try:
                if not wallet_address or not blockchain:
                    raise ValueError(self.translate("Wallet address and blockchain must be specified", "Wallet address and blockchain must be specified"))

                endpoints = {
                    'Tron': {
                        "url": f"{CONFIG['Tron']['base_url']}/transaction",
                        "params": {"address": wallet_address, "limit": 200},
                        "headers": {"TRON-PRO-API-KEY": CONFIG['Tron']['api_key']}
                    },
                    'Ethereum': {
                        "url": f"https://api.etherscan.io/api",
                        "params": {
                            "module": "account",
                            "action": "txlist",
                            "address": wallet_address,
                            "startblock": 0,
                            "endblock": 99999999,
                            "sort": "asc",
                            "apikey": CONFIG['Ethereum']['etherscan_api_key']
                        },
                        "headers": {}
                    },
                    'BSC': {
                        "url": CONFIG['BSC']['base_url'],
                        "params": {
                            "module": "account",
                            "action": "txlist",
                            "address": wallet_address,
                            "startblock": 0,
                            "endblock": 99999999,
                            "sort": "asc",
                            "apikey": CONFIG['BSC']['bscscan_api_key']
                        },
                        "headers": {}
                    },
                    'Linea': {
                        "url": CONFIG['Linea']['infura_url'],
                        "params": {
                            "module": "proxy",
                            "action": "eth_getLogs",
                            "fromBlock": "0",
                            "toBlock": "latest",
                            "address": wallet_address,
                        },
                        "headers": {}
                    }
                }

                if blockchain == 'Solana':
                    async with aiohttp.ClientSession() as session:
                        transactions = await self.fetch_transactions_solana(session, wallet_address)
                        tasks = [self.fetch_solana_block_time(session, tx.get("slot")) for tx in transactions]
                        block_times = await asyncio.gather(*tasks)
                        parsed_txs = []
                        for tx, block_time in zip(transactions, block_times):
                            parsed_tx = self._parse_solana_tx(tx, block_time)
                            if parsed_tx:
                                parsed_txs.append(parsed_tx)
                        return parsed_txs

                if blockchain == 'Linea':
                    async with aiohttp.ClientSession() as session:
                        return await self.fetch_transactions_linea(session, wallet_address)

                async def make_request():
                    endpoint = endpoints.get(blockchain)
                    if not endpoint:
                        self.log(self.translate(
                            f"Unsupported blockchain: {blockchain}",
                            f"Unsupported blockchain: {blockchain}"
                        ), "red")
                        return []

                    try:
                        async with aiohttp.ClientSession(timeout=self.timeout) as session:
                            async with session.get(endpoint["url"], 
                                                params=endpoint["params"],
                                                headers=endpoint["headers"]) as response:
                                response.raise_for_status()
                                return await response.json()
                    except aiohttp.ClientError as e:
                        self.log(self.translate(
                            f"API request error: {str(e)}",
                            f"API request error: {str(e)}"
                        ), "red")
                        return []

                retries = 3
                while retries > 0:
                    try:
                        data = await make_request()
                        if not data:
                            raise ValueError("Empty response received")
                        
                        if blockchain == 'Tron':
                            return data.get("data", [])
                        return data.get("result", [])
                    except Exception as e:
                        retries -= 1
                        if retries == 0:
                            self.log(self.translate(
                                f"Failed to fetch transactions after 3 attempts: {str(e)}",
                                f"Failed to fetch transactions after 3 attempts: {str(e)}"
                            ), "red")
                            return []
                        await self.sleep_func(1)

                if attempt > 0:
                    self.log(self.translate(
                        f"Successful after {attempt + 1} attempts",
                        f"Successful after {attempt + 1} attempts"
                    ), "yellow")
                
                return transactions

            except aiohttp.ClientError as e:
                if attempt == max_retries - 1:
                    self.log(self.translate(
                        f"API request failed after {max_retries} attempts: {str(e)}",
                        f"API request failed after {max_retries} attempts: {str(e)}"
                    ), "red")
                    return []
                
                self.log(self.translate(
                    f"Attempt {attempt + 1} failed, retrying...",
                    f"Attempt {attempt + 1} failed, retrying..."
                ), "yellow")
                await self.sleep_func(retry_delay * (attempt + 1))

        return []

    def analyze_transactions(self, transactions: List[Dict[str, Any]], blockchain: str) -> pd.DataFrame:
        if not isinstance(transactions, list):
            self.log(self.translate("Invalid transaction data format.", "Invalid transaction data format."), "red")
            return pd.DataFrame(columns=['hash', 'timestamp', 'ownerAddress', 'toAddress', 'amount', 'blockchain'])

        df = pd.DataFrame(columns=['hash', 'timestamp', 'ownerAddress', 'toAddress', 'amount', 'blockchain'])
        
        if not transactions:
            return df

        for tx in transactions:
            try:
                parsed_tx = self.parsers.get(blockchain, lambda x: x)(tx)
                if parsed_tx:
                    parsed_tx['blockchain'] = blockchain
                    df = pd.concat([df, pd.DataFrame([parsed_tx])], ignore_index=True)
            except Exception as e:
                self.log(self.translate(
                    f"Error parsing transaction: {str(e)}",
                    f"Error parsing transaction: {str(e)}"
                ), "red")
                continue

        df['amount'] = pd.to_numeric(df['amount'], errors='coerce')

        if not df.empty:
            self._print_transaction_summary(df, blockchain)
        
        return df

    async def execute_analysis(self, addresses: List[str]):
        """Modified execute_analysis with API verification"""
        if not addresses:
            self.log(self.translate(
                "No addresses provided for analysis.",
                "No addresses provided for analysis."
            ), "red")
            return

        api_status = await self.verify_api_keys()
        if not any(api_status.values()):
            self.log(self.translate(
                "No working APIs found. Please check your API keys.",
                "No working APIs found. Please check your API keys."
            ), "red")
            return

        try:
            all_transactions = pd.DataFrame(columns=['hash', 'timestamp', 'ownerAddress', 'toAddress', 'amount', 'blockchain'])
            
            self.log(self.translate(
                "Starting transaction analysis...",
                "Starting transaction analysis..."
            ), "green")
            wallet_addresses = self.validate_addresses(addresses)
            self.log(self.translate(
                f"Validated wallet addresses: {wallet_addresses}",
                f"Validated wallet addresses: {wallet_addresses}"
            ), "cyan")

            for blockchain, wallets in wallet_addresses.items():
                if not wallets:
                    continue
                    
                for wallet in wallets:
                    try:
                        transactions = await self.fetch_transactions(wallet, blockchain)
                        if transactions:
                            df = pd.DataFrame(transactions)
                            df['blockchain'] = blockchain
                            for col in ['hash', 'timestamp', 'ownerAddress', 'toAddress', 'amount']:
                                if col not in df.columns:
                                    df[col] = None
                            df['amount'] = pd.to_numeric(df['amount'], errors='coerce')
                            all_transactions = pd.concat([all_transactions, df], ignore_index=True)
                    except Exception as e:
                        self.log(self.translate(
                            f"Error analyzing {blockchain} wallet {wallet}: {str(e)}",
                            f"Error analyzing {blockchain} wallet {wallet}: {str(e)}"
                        ), "red")
                        continue

            if all_transactions.empty:
                self.log(self.translate(
                    "No transactions were analyzable from any wallet.",
                    "No transactions were analyzable from any wallet."
                ), "red")
                return

            suspicious_df = self.identify_suspicious_transactions(all_transactions)

            potential_exchanges = self.identify_exchange_addresses(suspicious_df)
            self.update_known_exchanges(potential_exchanges)

            potential_blacklist = self.identify_blacklist_addresses(suspicious_df)
            self.update_blacklist_addresses(potential_blacklist)

            suspicious_wallets_network = self.scan_for_suspicious_wallets(all_transactions)

            fraud_probability = self.calculate_probability_of_fraud(all_transactions, suspicious_wallets_network)

            fraud_probabilities = self.calculate_fraud_probability_for_final_addresses(all_transactions)

            suspicious_addresses = self.filter_suspicious_addresses_by_prob(fraud_probabilities)

            self.generate_report(fraud_probabilities, suspicious_addresses)

            self.save_to_csv(all_transactions)

            self.anomaly_detection(all_transactions)

            visited = set()
            exchange_paths = []
            for wallet_address in addresses:
                blockchain = self.detect_blockchain_from_address(wallet_address)
                if blockchain != 'Unknown':
                    await self.traverse_wallets(wallet_address, blockchain, 0, MAX_DEPTH, visited, exchange_paths)

        except Exception as e:
            self.log(self.translate(
                f"Analysis failed: {str(e)}",
                f"Analysis failed: {str(e)}"
            ), "red")
            raise

    def identify_suspicious_transactions(self, df: pd.DataFrame) -> pd.DataFrame:
        self.log(self.translate(
            "Identifying suspicious transactions...",
            "Identifying suspicious transactions..."
        ), "cyan")
        suspicious_df = pd.DataFrame()
        if 'blockchain' not in df.columns:
            self.log(self.translate("'blockchain' column is missing in the dataframe.", "'blockchain' column is missing in the dataframe."), "red")
            return suspicious_df

        for blockchain in CONFIG.keys():
            blockchain_df = df[df["blockchain"] == blockchain]
            threshold = CONFIG[blockchain].get("threshold", 0)
            high_value = blockchain_df[blockchain_df["amount"] > threshold]
            if not high_value.empty:
                self.log(self.translate(
                    f"\n**High-value Transactions in {blockchain}:**",
                    f"\n**High-value Transactions in {blockchain}:**"
                ), "magenta")
                self.log(high_value[["hash", "timestamp", "ownerAddress", "toAddress", "amount"]].to_string(index=False), "yellow")
                suspicious_df = pd.concat([suspicious_df, high_value], ignore_index=True)
        return suspicious_df

    def identify_exchange_addresses(self, df: pd.DataFrame) -> Set[str]:
        self.log(self.translate(
            "Identifying potential exchange addresses...",
            "Identifying potential exchange addresses..."
        ), "cyan")
        potential_exchanges = set()
        for blockchain in CONFIG.keys():
            blockchain_df = df[df["blockchain"] == blockchain]
            if blockchain_df.empty:
                continue
            address_counts = blockchain_df['toAddress'].value_counts()
            exchange_threshold = 50
            exchange_addresses = address_counts[address_counts > exchange_threshold].index.tolist()
            potential_exchanges.update(exchange_addresses)
        return potential_exchanges

    def identify_blacklist_addresses(self, df: pd.DataFrame) -> Set[str]:
        self.log(self.translate(
            "Identifying potential blacklist addresses...",
            "Identifying potential blacklist addresses..."
        ), "cyan")
        blacklist_candidates = set()
        if 'blockchain' not in df.columns:
            self.log(self.translate(
                "'blockchain' column is missing in the dataframe.",
                "'blockchain' column is missing in the dataframe."
            ), "red")
            return blacklist_candidates

        for blockchain in CONFIG.keys():
            blockchain_df = df[df["blockchain"] == blockchain]
            if blockchain_df.empty:
                continue
            grouped = blockchain_df.groupby('toAddress')
            for address, group in grouped:
                unique_senders = group['ownerAddress'].nunique()
                if unique_senders > 100:
                    blacklist_candidates.add(address)
        return blacklist_candidates

    def update_known_exchanges(self, potential_exchanges: Set[str]) -> None:
        self.log(self.translate(
            "Updating known exchanges...",
            "Updating known exchanges..."
        ), "cyan")
        new_exchanges = {}
        for exchange_address in potential_exchanges:
            blockchain = self.detect_blockchain_from_address(exchange_address)
            if blockchain != 'Unknown' and exchange_address not in self.known_exchanges.get(blockchain, []):
                self.known_exchanges.setdefault(blockchain, []).append(exchange_address)
                new_exchanges.setdefault(blockchain, []).append(exchange_address)

        if new_exchanges:
            self.log(self.translate(
                "\n**Adding new exchanges to known_exchanges.json:**",
                "\n**Adding new exchanges to known_exchanges.json:**"
            ), "cyan")
            for bc, addresses in new_exchanges.items():
                self.log(f"{bc}: {', '.join(addresses)}", "cyan")
            save_json_file(self.known_exchanges, KNOWN_EXCHANGES_FILE)
        else:
            self.log(self.translate(
                "\n**No new exchanges found to add to known_exchanges.json.**",
                "\n**No new exchanges found to add to known_exchanges.json.**"
            ), "yellow")

    def update_blacklist_addresses(self, potential_blacklist: Set[str]) -> None:
        self.log(self.translate(
            "Updating blacklist addresses...",
            "Updating blacklist addresses..."
        ), "cyan")
        new_blacklist = potential_blacklist - self.blacklist_addresses
        if new_blacklist:
            self.log(self.translate(
                "\n**Adding new addresses to blacklist_addresses.json:**",
                "\n**Adding new addresses to blacklist_addresses.json:**"
            ), "cyan")
            for address in new_blacklist:
                self.log(address, "red")
            self.blacklist_addresses.update(new_blacklist)
            save_json_file(list(self.blacklist_addresses), BLACKLIST_FILE)
        else:
            self.log(self.translate(
                "\n**No new addresses found to add to blacklist_addresses.json.**",
                "\n**No new addresses found to add to blacklist_addresses.json.**"
            ), "yellow")

    def scan_for_suspicious_wallets(self, df: pd.DataFrame) -> Set[str]:
        self.log(self.translate(
            "Scanning for suspicious wallets...",
            "Scanning for suspicious wallets..."
        ), "cyan")
        receiving_wallets = set(df["toAddress"].unique())

        known_exchange_wallets = set()
        for wallets in self.known_exchanges.values():
            known_exchange_wallets.update(wallets)
        receiving_wallets -= known_exchange_wallets
        receiving_wallets -= self.blacklist_addresses

        self.log(self.translate(
            "\n**Identified Suspicious Wallets:**",
            "\n**Identified Suspicious Wallets:**"
        ), "magenta")
        if not receiving_wallets:
            self.log(self.translate(
                "No suspicious wallets identified.",
                "No suspicious wallets identified."
            ), "yellow")
        else:
            self.log(", ".join(receiving_wallets), "red")

        suspicious_wallets_network = set()
        for _, row in df.iterrows():
            if row["toAddress"] in receiving_wallets:
                suspicious_wallets_network.add(row["ownerAddress"])

        self.log(self.translate(
            "\n**Suspicious Wallets Network:**",
            "\n**Suspicious Wallets Network:**"
        ), "magenta")
        if not suspicious_wallets_network:
            self.log(self.translate(
                "No wallets connected to suspicious wallets were found.",
                "No wallets connected to suspicious wallets were found."
            ), "yellow")
        else:
            self.log(", ".join(suspicious_wallets_network), "red")

        return suspicious_wallets_network

    def calculate_probability_of_fraud(self, df: pd.DataFrame, suspicious_wallets_network: Set[str]) -> float:
        self.log(self.translate(
            "Calculating probability of fraud...",
            "Calculating probability of fraud..."
        ), "cyan")
        total_wallets = len(df["toAddress"].unique())
        suspicious_wallets = len(suspicious_wallets_network)

        fraud_probability = (suspicious_wallets / total_wallets) * 100 if total_wallets else 0
        fraud_probability = min(fraud_probability, 100)

        connected_to_exchange = 0
        for wallet in suspicious_wallets_network:
            for exchange_wallets in self.known_exchanges.values():
                if wallet in exchange_wallets:
                    connected_to_exchange += 1
                    break

        exchange_connection_probability = (connected_to_exchange / suspicious_wallets) * 100 if suspicious_wallets else 0

        fraud_color = "red" if fraud_probability > 70 else "yellow" if fraud_probability > 40 else "green"
        exchange_color = "red" if exchange_connection_probability > 50 else "yellow" if exchange_connection_probability > 20 else "green"

        self.log(self.translate(
            "\n**Probability of Fraud Involvement:**",
            "\n**Probability of Fraud Involvement:**"
        ), "magenta")
        self.log(f"{fraud_probability:.2f}%", fraud_color)
        self.log(self.translate(
            "\n**Probability of Wallets Connecting to Exchanges:**",
            "\n**Probability of Wallets Connecting to Exchanges:**"
        ), "magenta")
        self.log(f"{exchange_connection_probability:.2f}%", exchange_color)

        return fraud_probability

    def anomaly_detection(self, df: pd.DataFrame, canvas_parent=None) -> None:
        self.log(self.translate(
            "Performing anomaly detection...",
            "Performing anomaly detection..."
        ), "cyan")
        if df.empty:
            self.log(self.translate(
                "Empty dataframe received for anomaly detection.",
                "Empty dataframe received for anomaly detection."
            ), "yellow")
            return

        features = df[['amount']]
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        iso_forest = IsolationForest(contamination=0.05, random_state=42)
        df['anomaly'] = iso_forest.fit_predict(scaled_features)
        anomalies = df[df['anomaly'] == -1]
        self.log(self.translate(
            "\n**Identified Anomalous Transactions:**",
            "\n**Identified Anomalous Transactions:**"
        ), "magenta")
        if anomalies.empty:
            self.log(self.translate(
                "No anomalous transactions found.",
                "No anomalous transactions found."
            ), "yellow")
        else:
            self.log(anomalies[['hash', 'timestamp', 'ownerAddress', 'toAddress', 'amount']].to_string(index=False), "red")
            self.plot_anomalies(anomalies, canvas_parent)

    def calculate_fraud_probability_for_final_addresses(self, df: pd.DataFrame, canvas_parent=None) -> List[tuple]:
        self.log(self.translate(
            "Calculating fraud probability for final addresses...",
            "Calculating fraud probability for final addresses..."
        ), "cyan")
        address_counts = Counter(df["toAddress"])

        fraud_probabilities = []
        for address, count in address_counts.items():
            if address in self.blacklist_addresses:
                fraud_probabilities.append((address, 100.0, self.translate("Listed in blacklist", "Listed in blacklist")))
                continue
            fraud_probability = (count / len(df)) * 100
            is_exchange = any(address in wallets for wallets in self.known_exchanges.values())
            if is_exchange:
                fraud_probability -= 50
                reason = self.translate("Connected to known exchange", "Connected to known exchange")
            else:
                reason = self.translate("High transaction count", "High transaction count")
            fraud_probability = max(fraud_probability, 0)
            fraud_probabilities.append((address, fraud_probability, reason))

        self.log(self.translate(
            "\n**Fraud Probability for Final Addresses:**",
            "\n**Fraud Probability for Final Addresses:**"
        ), "magenta")
        for address, prob, reason in fraud_probabilities:
            color = "red" if prob > FRAUD_PROBABILITY_THRESHOLD else "yellow"
            self.log(f"{self.translate('Address', 'Address')}: {address}, {self.translate('Fraud Probability', 'Fraud Probability')}: {prob:.2f}%, {self.translate('Reason', 'Reason')}: {reason}", color)

        self.plot_fraud_probabilities(fraud_probabilities, canvas_parent)

        return fraud_probabilities

    def filter_suspicious_addresses_by_prob(self, fraud_probabilities: List[tuple], threshold: int = FRAUD_PROBABILITY_THRESHOLD) -> List[str]:
        self.log(self.translate(
            "Filtering suspicious addresses based on probability...",
            "Filtering suspicious addresses based on probability..."
        ), "cyan")
        suspicious_addresses = [address for address, prob, _ in fraud_probabilities if prob > threshold]

        self.log(self.translate(
            "\n**Identified Suspicious Addresses:**",
            "\n**Identified Suspicious Addresses:**"
        ), "magenta")
        if not suspicious_addresses:
            self.log(self.translate(
                "No addresses with high fraud probability were found.",
                "No addresses with high fraud probability were found."
            ), "yellow")
        else:
            self.log(", ".join(suspicious_addresses), "red")
        return suspicious_addresses

    def generate_report(self, fraud_probabilities: List[tuple], suspicious_addresses: List[str], filename: str = "report.html") -> None:
        self.log(self.translate(
            f"Generating report and saving to {filename}...",
            f"Generating report and saving to {filename}..."
        ), "cyan")
        html_content = f"""
        <html>
        <head>
            <title>Transaction Analysis Report</title>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #121212;
                    color: #FFFFFF;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    width: 80%;
                    margin: auto;
                    padding: 20px;
                }}
                h1, h2 {{
                    color: #00ff9d;
                    text-align: center;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-bottom: 20px;
                }}
                th, td {{
                    padding: 10px;
                    text-align: left;
                    border-bottom: 1px solid #555555;
                }}
                th {{
                    background-color: #1E1E1E;
                }}
                tr:hover {{
                    background-color: #333333;
                }}
                .recommendations, .disclaimer, .support {{
                    margin-top: 20px;
                    padding: 15px;
                    border: 1px solid #333333;
                    border-radius: 8px;
                    background-color: #1E1E1E;
                }}
                .recommendations ol, .disclaimer p, .support p {{
                    margin: 0;
                    padding: 0;
                }}
                .recommendations ol {{
                    padding-left: 20px;
                }}
                .support a {{
                    color: #FFDC00;
                    text-decoration: none;
                }}
                .support a:hover {{
                    text-decoration: underline;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>Transaction Analysis Report</h1>
                <h2>Fraud Probability for Final Addresses</h2>
                <table>
                    <tr>
                        <th>Address</th>
                        <th>Fraud Probability (%)</th>
                        <th>Reason</th>
                    </tr>
        """
        for address, prob, reason in fraud_probabilities:
            color = "#FF4136" if prob > FRAUD_PROBABILITY_THRESHOLD else "#FFDC00"
            html_content += f"""
                    <tr>
                        <td>{address}</td>
                        <td style="color: {color};">{prob:.2f}%</td>
                        <td>{reason}</td>
                    </tr>
            """
        html_content += """
                </table>
                <h2>Identified Suspicious Addresses</h2>
                <ul>
        """
        for addr in suspicious_addresses:
            html_content += f"<li style='color: #FF4136;'>{addr}</li>"
        html_content += """
                </ul>
                <div class="recommendations">
                    <h2>Recommendations:</h2>
                    <ol>
                        <li>Investigate high-value transactions and involved wallet addresses.</li>
                        <li>Monitor the network of suspicious wallets for any unusual activity.</li>
                        <li>Report findings to relevant authorities or platforms.</li>
                    </ol>
                    <p>If no fraud is observed, please continue to exercise caution.</p>
                </div>
                <div class="disclaimer">
                    <h2>Disclaimer:</h2>
                    <p>This analysis provides an estimated probability based on transaction data. For a more comprehensive and specialized review, please contact our support team.</p>
                </div>
                <div class="support">
                    <h2>Support:</h2>
                    <p>If you need expert assistance, please <a href="mailto:support@v7lthronix">contact us</a>.</p>
                </div>
            </div>
        </body>
        </html>
        """
        try:
            with open(filename, 'w', encoding='utf-8') as file:
                file.write(html_content)
            self.log(self.translate(
                f"\n**Comprehensive report generated and saved to '{filename}'.**",
                f"\n**Comprehensive report generated and saved to '{filename}'.**"
            ), "green")
        except Exception as e:
            self.log(self.translate(
                f"Error generating report: {e}",
                f"Error generating report: {e}"
            ), "red")

    def save_to_csv(self, df: pd.DataFrame, filename: str = "transaction_analysis.csv") -> None:
        self.log(self.translate(
            f"Saving analysis to {filename}...",
            f"Saving analysis to {filename}..."
        ), "cyan")
        try:
            df.to_csv(filename, index=False)
            self.log(self.translate(
                f"\n**Analysis saved to '{filename}'.**",
                f"\n**Analysis saved to '{filename}'.**"
            ), "green")
        except Exception as e:
            self.log(self.translate(
                f"Error saving to CSV: {e}",
                f"Error saving to CSV: {e}"
            ), "red")

    async def traverse_wallets(self, wallet_address: str, blockchain: str, current_depth: int, max_depth: int, visited: Set[str], exchange_paths: List[List[str]]) -> None:
        if current_depth > max_depth or wallet_address in visited:
            return

        visited.add(wallet_address)
        path = [wallet_address]

        try:
            transactions = await self.fetch_transactions(wallet_address, blockchain)
        except Exception as e:
            self.log(self.translate(
                f"Error fetching transactions for {wallet_address}: {e}",
                f"Error fetching transactions for {wallet_address}: {e}"
            ), "red")
            return

        df = self.analyze_transactions(transactions, blockchain)

        if not df.empty:
            for _, tx in df.iterrows():
                to_address = tx.get('toAddress')
                if not to_address:
                    continue

                exchange = self.is_exchange_address(to_address)
                if exchange:
                    exchange_paths.append(path + [to_address])
                    self.log(self.translate(
                        f"**Exchange {exchange} found at address {to_address} via path:** {' -> '.join(path + [to_address])}",
                        f"**Exchange {exchange} found at address {to_address} via path:** {' -> '.join(path + [to_address])}"
                    ), "green")
                    continue

                if to_address not in visited:
                    await self.traverse_wallets(to_address, blockchain, current_depth + 1, max_depth, visited, exchange_paths)

    def is_exchange_address(self, address: str) -> str:
        for exchange, addresses in self.known_exchanges.items():
            if address in addresses:
                return exchange
        return ''

    def plot_transactions(self, df: pd.DataFrame, blockchain: str, canvas_parent=None) -> None:
        if df.empty:
            self.log(self.translate("No data available for plotting.", "No data available for plotting."), "yellow")
            return

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.bar(df.index, df['amount'], color='green')
        ax.set_title(self.translate(f'Transaction Amounts for {blockchain}', f'Transaction Amounts for {blockchain}'))
        ax.set_xlabel(self.translate('Transaction Number', 'Transaction Number'))
        ax.set_ylabel(f"Amount ({CONFIG[blockchain]['unit']})")
        plt.tight_layout()

        if canvas_parent:
            canvas = FigureCanvas(fig)
            canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            canvas.updateGeometry()
            canvas_parent.layout().addWidget(canvas)
        else:
            plt.show()

        plt.close(fig)

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.plot(df['timestamp'], df['amount'], color='blue')
        ax.set_title(self.translate(f'Transaction Amounts for {blockchain} Over Time', f'Transaction Amounts for {blockchain} Over Time'))
        ax.set_xlabel(self.translate('Time', 'Time'))
        ax.set_ylabel(f"Amount ({CONFIG[blockchain]['unit']})")
        plt.tight_layout()

        if canvas_parent:
            canvas = FigureCanvas(fig)
            canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            canvas.updateGeometry()
            canvas_parent.layout().addWidget(canvas)
        else:
            plt.show()

        plt.close(fig)

    def plot_anomalies(self, anomalies: pd.DataFrame, canvas_parent=None) -> None:
        if anomalies.empty:
            self.log(self.translate(
                "No anomalies found to plot.",
                "No anomalies found to plot."
            ), "yellow")
            return

        fig, ax = plt.subplots(figsize=(10, 6))
        ax.scatter(anomalies.index, anomalies['amount'], color='red')
        ax.set_title(self.translate('Anomalous Transactions', 'Anomalous Transactions'))
        ax.set_xlabel(self.translate('Transaction Number', 'Transaction Number'))
        ax.set_ylabel(self.translate('Amount', 'Amount'))
        plt.tight_layout()

        if canvas_parent:
            canvas = FigureCanvas(fig)
            canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            canvas.updateGeometry()
            canvas_parent.layout().addWidget(canvas)
        else:
            plt.show()

        plt.close(fig)

    def plot_fraud_probabilities(self, fraud_probabilities: List[tuple], canvas_parent=None) -> None:
        addresses = [fp[0] for fp in fraud_probabilities]
        probabilities = [fp[1] for fp in fraud_probabilities]

        fig, ax = plt.subplots(figsize=(12, 8))
        bars = ax.bar(addresses, probabilities, color=['red' if prob > FRAUD_PROBABILITY_THRESHOLD else 'yellow' for prob in probabilities])
        ax.set_xlabel(self.translate('Addresses', 'Addresses'))
        ax.set_ylabel(self.translate('Fraud Probability (%)', 'Fraud Probability (%)'))
        ax.set_title(self.translate('Fraud Probability for Final Addresses', 'Fraud Probability for Final Addresses'))
        plt.xticks(rotation=90)
        plt.tight_layout()

        if canvas_parent:
            canvas = FigureCanvas(fig)
            canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            canvas.updateGeometry()
            canvas_parent.layout().addWidget(canvas)
        else:
            plt.show()

        plt.close(fig)

    def _validate_blockchain(self, blockchain: str) -> bool:
        return blockchain in CONFIG.keys()

    def _validate_transaction(self, tx: Dict[str, Any]) -> bool:
        required_fields = {'hash', 'timestamp', 'ownerAddress', 'toAddress', 'amount'}
        return all(field in tx for field in required_fields)

    async def _make_api_request(self, session: aiohttp.ClientSession, url: str, 
                              params: Dict = None, headers: Dict = None) -> Dict:
        retries = 3
        while retries > 0:
            try:
                async with session.get(url, params=params, headers=headers) as response:
                    response.raise_for_status()
                    return await response.json()
            except Exception as e:
                retries -= 1
                if retries == 0:
                    raise
                await self.sleep_func(1)

    def _print_transaction_summary(self, df: pd.DataFrame, blockchain: str) -> None:
        self.log(self.translate(
            f"\n**Transaction Summary for {blockchain}:**",
            f"\n**Transaction Summary for {blockchain}:**"
        ), "magenta")
        
        self.log(self.translate(
            f"Total Transactions: {len(df)}",
            f"Total Transactions: {len(df)}"
        ), "cyan")
        
        if blockchain in CONFIG:
            threshold = CONFIG[blockchain].get("threshold", 0)
            high_value = df[df["amount"] > threshold]
            if not high_value.empty:
                self.log(self.translate(
                    f"High-value Transactions: {len(high_value)}",
                    f"High-value Transactions: {len(high_value)}"
                ), "yellow")
                self.log(self.translate("Sample Transactions:", "Sample Transactions:"), "yellow")
                sample_cols = ["hash", "timestamp", "ownerAddress", "toAddress", "amount"]
                if all(col in high_value.columns for col in sample_cols):
                    self.log(high_value[sample_cols].head().to_string(), "yellow")
            else:
                self.log(self.translate(
                    "No high-value transactions found.",
                    "No high-value transactions found."
                ), "green")

    async def verify_api_keys(self):
        """Enhanced API verification with new chains"""
        self.log(self.translate("Verifying API connections...", "Verifying API connections..."), "cyan")
        
        test_results = {}
        
        async def test_api(chain: str, url: str, params: dict = None, headers: dict = None):
            if not any(CONFIG[chain].values()):
                return False
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(url, params=params, headers=headers) as response:
                        return response.status == 200
            except:
                return False

        test_configs = {
            "Polygon": {
                "url": f"{CONFIG['Polygon']['base_url']}",
                "params": {"module": "proxy", "action": "eth_blockNumber", "apikey": CONFIG['Polygon']['polygonscan_api_key']}
            },
            "Avalanche": {
                "url": f"{CONFIG['Avalanche']['base_url']}",
                "params": {"module": "proxy", "action": "eth_blockNumber", "apikey": CONFIG['Avalanche']['snowtrace_api_key']}
            },
            "Fantom": {
                "url": f"{CONFIG['Fantom']['base_url']}",
                "params": {"module": "proxy", "action": "eth_blockNumber", "apikey": CONFIG['Fantom']['ftmscan_api_key']}
            },
            "Arbitrum": {
                "url": f"{CONFIG['Arbitrum']['base_url']}",
                "params": {"module": "proxy", "action": "eth_blockNumber", "apikey": CONFIG['Arbitrum']['arbiscan_api_key']}
            },
            "Optimism": {
                "url": f"{CONFIG['Optimism']['base_url']}",
                "params": {"module": "proxy", "action": "eth_blockNumber", "apikey": CONFIG['Optimism']['optimistic_api_key']}
            }
        }
        
        test_configs.update({
            "Tron": {"url": f"{CONFIG['Tron']['base_url']}/transaction", "headers": {"TRON-PRO-API-KEY": CONFIG['Tron']['api_key']}},
            "Ethereum": {"url": "https://api.etherscan.io/api", "params": {"module": "proxy", "action": "eth_blockNumber", "apikey": CONFIG['Ethereum']['etherscan_api_key']}}
        })

        for chain, config in test_configs.items():
            try:
                result = await test_api(chain, **config)
                test_results[chain] = result
                status = "green" if result else "red"
                self.log(f"{chain} API: {'✓' if result else '✗'}", status)
            except Exception as e:
                test_results[chain] = False
                self.log(f"{chain} API Error: {str(e)}", "red")
        
        return test_results

def preprocess_data(file_path):
    try:
        data = pd.read_csv(file_path)
        if 'label' not in data.columns:
            print(colored("Warning: No label column found in data", "yellow"))
            return None, None, None, None
        X = data.drop('label', axis=1)
        y = data['label']
        return train_test_split(X, y, test_size=0.2, random_state=42)
    except FileNotFoundError:
        print(colored(f"Error: Could not find file {file_path}", "red"))
        return None, None, None, None
    except Exception as e:
        print(colored(f"Error processing data: {str(e)}", "red"))
        return None, None, None, None

def train_model(X_train, y_train):
    if X_train is None or y_train is None:
        return None
    try:
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train, y_train)
        model_path = 'models/transaction_model.joblib'
        os.makedirs('models', exist_ok=True)
        dump(model, model_path)
        print(colored("Model trained and saved successfully", "green"))
        return model
    except Exception as e:
        print(colored(f"Error training model: {str(e)}", "red"))
        return None

def evaluate_model(model, X_test, y_test):
    if model is None or X_test is None or y_test is None:
        return None
    try:
        y_pred = model.predict(X_test)
        report = classification_report(y_test, y_pred)
        print(colored("Model Evaluation:", "cyan"))
        print(report)
        return report
    except Exception as e:
        print(colored(f"Error evaluating model: {str(e)}", "red"))
        return None

def predict_new_transactions(model, file_path):
    try:
        new_transactions = pd.read_csv(file_path)
        predictions = model.predict(new_transactions)
        return predictions
    except FileNotFoundError:
        print(colored(f"Error: Could not find file {file_path}", "red"))
        return None
    except Exception as e:
        print(colored(f"Error making predictions: {str(e)}", "red"))
        return None
