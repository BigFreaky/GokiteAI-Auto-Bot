// Core Node.js modules for file system and readline interface
import fs from 'fs/promises';
import { createInterface } from 'readline/promises';
import crypto from 'crypto';

// External libraries for various functionalities
import dotenv from 'dotenv'; // For loading environment variables from .env file
import axios from 'axios'; // For making HTTP requests
import { HttpsProxyAgent } from 'https-proxy-agent'; // For HTTPS proxy support
import { SocksProxyAgent } from 'socks-proxy-agent'; // For SOCKS proxy support
import { ethers } from 'ethers'; // For Ethereum wallet and address operations
import randomUseragent from 'random-useragent'; // For generating random user agents
import ora from 'ora'; // For terminal spinners
import chalk from 'chalk'; // For colorful terminal output
import moment from 'moment-timezone'; // For date and time formatting with timezones
import { createParser } from 'eventsource-parser'; // For parsing Server-Sent Events (SSE)
import figlet from 'figlet'; // For ASCII art banners


// Load environment variables from the .env file.
// This should be called as early as possible in your application.
dotenv.config();

// --- Utility Functions ---

/**
 * Returns the current timestamp formatted for Asia/Dhaka timezone.
 * @returns {string} Formatted timestamp.
 */
function getTimestamp() {
  return moment().tz('Asia/Dhaka').format('D/M/YYYY, HH:mm:ss');
}

/**
 * Displays a colorful ASCII art banner in the console with updated details,
 * centered and with a thin line border.
 */
function displayBanner() {
  const width = process.stdout.columns || 80; // Use actual terminal width, default to 80
  const bannerText = 'EARNINGDROP';
  const telegramText = '- Telegram Channel: EARNINGDROP | Link: https://t.me/earningdropshub -';
  const botDescriptionText = 'KITEAI AUTOMATED BOT DESIGNED FOR DAILY AI INTERACTIONS';

  // Use a fixed max length for content to calculate padding
  // Removed unixTimestampText.length from here
  const contentWidth = Math.max(
    figlet.textSync(bannerText, { font: "ANSI Shadow", horizontalLayout: 'full' }).split('\n')[0].length,
    telegramText.length,
    botDescriptionText.length
  );
  // Ensure the border is wide enough for content, but not less than 50 or more than terminal width
  const borderWidth = Math.min(width - 4, Math.max(50, contentWidth + 6)); // Add padding for border

  const borderLine = '─'.repeat(borderWidth);
  const padAmount = Math.floor((width - borderWidth) / 2);
  const padding = ' '.repeat(padAmount > 0 ? padAmount : 0); // Ensure padding is not negative

  console.log(chalk.gray(padding + '┌' + borderLine + '┐'));

  const bannerLines = figlet.textSync('\n ' + bannerText, { font: "ANSI Shadow", horizontalLayout: 'fitted' }).split('\n');
  bannerLines.forEach(line => {
    if (line.trim() === '') return; // Skip empty lines from figlet
    const centeredLine = line.padStart(line.length + Math.floor((borderWidth - line.length) / 2));
    console.log(chalk.gray(padding + '│') + chalk.cyanBright(centeredLine.padEnd(borderWidth)) + chalk.gray('│'));
  });

  // Centering helper for content lines
  const centerContent = (text, color) => {
    const centeredText = text.padStart(text.length + Math.floor((borderWidth - text.length) / 2));
    console.log(chalk.gray(padding + '│') + color(centeredText.padEnd(borderWidth)) + chalk.gray('│'));
  };

  console.log(chalk.gray(padding + '├' + '─'.repeat(borderWidth) + '┤')); // Separator line

  centerContent(telegramText, chalk.cyanBright);
  centerContent(botDescriptionText, chalk.yellowBright);

  console.log(chalk.gray(padding + '└' + borderLine + '┘'));
  console.log('\n'); // Add a final newline for spacing
}

// Create a readline interface for user input.
const rl = createInterface({
  input: process.stdin,
  output: process.stdout,
});

/**
 * Prompts the user for input.
 * @param {string} question The question to ask the user.
 * @returns {Promise<string>} The user's trimmed answer.
 */
async function promptUser(question) {
  const answer = await rl.question(chalk.white(question));
  return answer.trim();
}

/**
 * Pauses execution for a specified duration.
 * @param {number} ms The number of milliseconds to sleep.
 * @returns {Promise<void>} A promise that resolves after the delay.
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

let isSpinnerActive = false; // Flag to track if an Ora spinner is active

/**
 * Clears the current console line.
 */
async function clearConsoleLine() {
  process.stdout.clearLine(0);
  process.stdout.cursorTo(0);
}

/**
 * Types text to the console character by character for a visual effect.
 * @param {string} text The text to type.
 * @param {chalk.ChalkFunction} color The chalk color function to use.
 * @param {boolean} [noType=false] If true, prints the text instantly without typing effect.
 */
async function typeText(text, color, noType = false) {
  if (isSpinnerActive) await sleep(500); // Wait if a spinner is active
  const maxLength = 80;
  const displayText = text.length > maxLength ? text.slice(0, maxLength) + '...' : text;

  if (noType) {
    console.log(color(` ┊ │ ${displayText}`));
    return;
  }

  const totalTime = 200; // Total time for typing effect
  const sleepTime = displayText.length > 0 ? totalTime / displayText.length : 1; // Time per character

  console.log(color(' ┊ ┌── Response Chat API ──'));
  process.stdout.write(color(' ┊ │ '));
  for (const char of displayText) {
    process.stdout.write(char);
    await sleep(sleepTime);
  }
  process.stdout.write('\n');
  console.log(color(' ┊ └──'));
}

/**
 * Creates a simple progress bar string.
 * @param {number} current Current progress value.
 * @param {number} total Total progress value.
 * @returns {string} The progress bar string.
 */
function createProgressBar(current, total) {
  const barLength = 30;
  const filled = Math.round((current / total) * barLength);
  return `[${'█'.repeat(filled)}${' '.repeat(barLength - filled)} ${current}/${total}]`;
}

/**
 * Displays a header text, optionally clearing the console.
 * @param {string} text The header text.
 * @param {chalk.ChalkFunction} color The chalk color function to use.
 * @param {boolean} [forceClear=false] If true, clears the console before displaying.
 */
function displayHeader(text, color, forceClear = false) {
  if (isSpinnerActive) return; // Don't display header if spinner is active
  if (forceClear) console.clear();
  console.log(color(text));
}

/**
 * Validates if a string is a valid Ethereum private key format.
 * @param {string} pk The private key string.
 * @returns {boolean} True if valid, false otherwise.
 */
function isValidPrivateKey(pk) {
  return /^0x[a-fA-F0-9]{64}$|^[a-fA-F0-9]{64}$/.test(pk);
}

/**
 * Generates an authentication token using AES-256-GCM encryption.
 * @param {string} message The message to encrypt (EOA address).
 * @param {string} secretKey The secret key for encryption (hex string).
 * @returns {string} The generated authentication token (hex string).
 */
function generateAuthToken(message, secretKey) {
  const key = Buffer.from(secretKey, 'hex');
  const iv = crypto.randomBytes(12); // Initialization Vector
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv, {
    authTagLength: 16
  });
  let encrypted = cipher.update(message, 'utf8');
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  const authTag = cipher.getAuthTag(); // Authentication tag for GCM
  const result = Buffer.concat([iv, encrypted, authTag]);
  return result.toString('hex');
}

/**
 * Creates an Axios agent based on the proxy string.
 * @param {string | null} proxy The proxy string (e.g., 'http://user:pass@host:port' or 'socks5://user:pass@host:port').
 * @returns {HttpsProxyAgent | SocksProxyAgent | null} The proxy agent or null if no proxy.
 */
function createProxyAgent(proxy) {
  if (!proxy) return null;
  if (proxy.startsWith('http://') || proxy.startsWith('https://')) {
    return new HttpsProxyAgent(proxy);
  } else if (proxy.startsWith('socks://') || proxy.startsWith('socks4://') || proxy.startsWith('socks5://')) {
    return new SocksProxyAgent(proxy);
  }
  console.warn(chalk.yellow(`Warning: Unsupported proxy protocol for ${proxy}. Skipping proxy.`));
  return null;
}

// --- API Interaction Functions ---

/**
 * Retrieves the smart account address for a given EOA address.
 * @param {string} eoa The EOA address.
 * @param {string | null} proxy The proxy string to use.
 * @returns {Promise<string>} The smart account address.
 * @throws {Error} If the smart account address cannot be retrieved.
 */
async function getSmartAccountAddress(eoa, proxy = null) {
  await sleep(500);
  await clearConsoleLine();
  const spinChars = ['|', '/', '-', '\\'];
  let spinIndex = 0;
  let spinTimeout;
  isSpinnerActive = true;

  async function spin() {
    if (!isSpinnerActive) return;
    process.stdout.write(chalk.cyan(` ┊ → Fetching smart account address... ${spinChars[spinIndex]}\r`));
    spinIndex = (spinIndex + 1) % spinChars.length;
    spinTimeout = setTimeout(spin, 120);
  }
  spin();

  try {
    const payload = {
      jsonrpc: "2.0",
      id: 0,
      method: "eth_call",
      params: [
        {
          data: `0x8cb84e18000000000000000000000000${eoa.slice(2)}4b6f5b36bb7706150b17e2eecb6e602b1b90b94a4bf355df57466626a5cb897b`,
          to: "0x948f52524Bdf595b439e7ca78620A8f843612df3",
        },
        "latest",
      ],
    };
    let config = { headers: { 'Content-Type': 'application/json' } };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    const response = await axios.post('https://rpc-testnet.gokite.ai/', payload, config);
    const result = response.data.result;

    if (!result || result === '0x') throw new Error('Invalid eth_call response');

    const aa_address = '0x' + result.slice(26);
    await clearConsoleLine();
    clearTimeout(spinTimeout);
    await clearConsoleLine();
    console.log(chalk.green(` ┊ ✓ Smart account address: ${aa_address.slice(0, 8)}...`));
    await sleep(500);
    return aa_address;
  } catch (err) {
    await clearConsoleLine();
    clearTimeout(spinTimeout);
    await clearConsoleLine();
    console.log(chalk.red(` ┊ ✗ Failed to fetch smart account address: ${err.message}`));
    await sleep(500);
    throw err;
  } finally {
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Authenticates with the Kite AI platform.
 * @param {string} eoa The EOA address.
 * @param {string} privateKey The private key (not sent to API, used for local derivation/auth token).
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<{aa_address: string, access_token: string}>} Authentication details.
 * @throws {Error} If authentication fails after retries.
 */
async function authenticate(eoa, privateKey, proxy = null, retryCount = 0) {
  const maxRetries = 5;
  await clearConsoleLine();
  const spinChars = ['|', '/', '-', '\\'];
  let spinIndex = 0;
  let spinTimeout;
  isSpinnerActive = true;

  async function spin() {
    if (!isSpinnerActive) return;
    process.stdout.write(chalk.cyan(` ┊ → Authenticating${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}... ${spinChars[spinIndex]}\r`));
    spinIndex = (spinIndex + 1) % spinChars.length;
    spinTimeout = setTimeout(spin, 120);
  }
  spin();

  try {
    await clearConsoleLine();
    clearTimeout(spinTimeout);
    isSpinnerActive = false; // Temporarily deactivate spinner for getSmartAccountAddress
    await clearConsoleLine();

    const aa_address = await getSmartAccountAddress(eoa, proxy);
    const secretKey = '6a1c35292b7c5b769ff47d89a17e7bc4f0adfe1b462981d28e0e9f7ff20b8f8a'; // Hardcoded secret key
    const authToken = generateAuthToken(eoa, secretKey); // Generate auth token

    let config = {
      headers: {
        'Content-Type': 'application/json',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.9,id;q=0.8',
        'Authorization': authToken,
        'Origin': 'https://testnet.gokite.ai',
        'Referer': 'https://testnet.gokite.ai/',
        'User-Agent': randomUseragent.getRandom(),
      },
    };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    isSpinnerActive = true; // Reactivate spinner for authentication API call
    spin();
    const response = await axios.post('https://neo.prod.gokite.ai/v2/signin', { eoa, aa_address }, config);
    const { aa_address: response_aa_address, access_token } = response.data.data;

    if (!response_aa_address || !access_token) throw new Error('Invalid response: aa_address or access_token missing');

    await clearConsoleLine();
    clearTimeout(spinTimeout);
    await clearConsoleLine();
    console.log(chalk.green(` ┊ ✓ Authentication successful: aa_address=${response_aa_address.slice(0, 8)}...`));
    await sleep(500);
    return { aa_address: response_aa_address, access_token };
  } catch (err) {
    if (retryCount < maxRetries - 1) {
      await clearConsoleLine();
      clearTimeout(spinTimeout);
      await clearConsoleLine();
      process.stdout.write(chalk.cyan(` ┊ → Authenticating [Retry #${retryCount + 1}/${maxRetries}] ${spinChars[spinIndex]}\r`));
      await sleep(5000);
      return authenticate(eoa, privateKey, proxy, retryCount + 1);
    }
    await clearConsoleLine();
    clearTimeout(spinTimeout);
    await clearConsoleLine();
    console.log(chalk.red(` ┊ ✗ Authentication failed: ${err.message}`));
    await sleep(500);
    throw err;
  } finally {
    clearTimeout(spinTimeout);
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Logs in to the Ozone Point System.
 * @param {string} eoa The EOA address.
 * @param {string} aa_address The smart account address.
 * @param {string} access_token The access token from authentication.
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<object>} User profile data.
 * @throws {Error} If login fails after retries.
 */
async function login(eoa, aa_address, access_token, proxy = null, retryCount = 0) {
  const maxRetries = 5;
  await clearConsoleLine();
  const spinner = ora({ text: chalk.cyan(` ┊ → Logging in${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}`), prefixText: '', spinner: 'bouncingBar', interval: 120 }).start();
  isSpinnerActive = true;

  try {
    let config = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${access_token}`,
      },
    };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    const payload = {
      registration_type_id: 1,
      user_account_id: "", // These might be populated by the platform
      user_account_name: "", // These might be populated by the platform
      eoa_address: eoa,
      smart_account_address: aa_address,
      referral_code: "", // If you have a referral code, you might put it here
    };
    const response = await axios.post('https://ozone-point-system.prod.gokite.ai/auth', payload, config);
    const profile = response.data.data.profile;

    if (!profile) throw new Error('Invalid response: profile missing');

    spinner.succeed(chalk.green(` ┊ ✓ Login successful!`));
    await sleep(500);
    return profile;
  } catch (err) {
    if (err.response?.data?.error === 'User already exists') {
      spinner.succeed(chalk.green(` ┊ ✓ Login successful! (User already exists)`));
      await sleep(500);
      return { user_id: 'existing_user', eoa, aa_address }; // Return a simplified profile for existing users
    }
    if (retryCount < maxRetries - 1) {
      spinner.text = chalk.cyan(` ┊ → Logging in [Retry #${retryCount + 1}/${maxRetries}]`);
      await sleep(5000);
      return login(eoa, aa_address, access_token, proxy, retryCount + 1);
    }
    spinner.fail(chalk.red(` ┊ ✗ Login failed: ${err.message}`));
    await sleep(500);
    throw err;
  } finally {
    spinner.stop();
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Sends a chat message to an AI agent.
 * @param {string} access_token The access token.
 * @param {string} service_id The ID of the AI agent service.
 * @param {string} message The message to send.
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<string>} The full AI response.
 * @throws {Error} If chat fails after retries.
 */
async function chatWithAI(access_token, service_id, message, proxy = null, retryCount = 0) {
  const maxRetries = 5;
  await clearConsoleLine();
  const spinner = ora({
    text: chalk.cyan(` ┊ → Sending chat to ${service_id.slice(0, 20)}...${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}`),
    prefixText: '',
    spinner: 'bouncingBar',
    interval: 120
  }).start();
  isSpinnerActive = true;
  const isSherlock = service_id === "deployment_OX7sn2D0WvxGUGK8CTqsU5VJ"; // Sherlock agent has different display behavior

  try {
    const config = {
      headers: {
        'Accept': 'text/event-stream',
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${access_token}`,
        'User-Agent': randomUseragent.getRandom(),
      },
      responseType: 'stream', // Important for handling streaming responses
    };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    const payload = {
      service_id,
      subnet: "kite_ai_labs",
      stream: true, // Request streaming response
      body: { stream: true, message },
    };
    const response = await axios.post(
      'https://ozone-point-system.prod.gokite.ai/agent/inference',
      payload,
      config
    );

    let fullResponse = '';
    let buffer = '';
    // Process streaming data chunk by chunk
    response.data.on('data', chunk => {
      buffer += chunk.toString('utf8');
      const parts = buffer.split(/\r?\n\r?\n/); // Split by double newlines (SSE message delimiter)
      buffer = parts.pop(); // Keep incomplete part for next chunk

      for (const part of parts) {
        if (!part.startsWith('data:')) continue; // Only process data lines
        const data = part.replace(/^data:\s*/, '').trim();
        if (data === '[DONE]') continue; // End of stream marker

        try {
          const json = JSON.parse(data);
          const delta = json.choices?.[0]?.delta?.content; // Extract content delta
          if (!delta) continue;
          fullResponse += delta;
          if (!isSherlock) {
            spinner.clear(); // Clear spinner to show partial response
            spinner.render();
          }
        } catch (parseError) {
          // console.error(chalk.red(`Error parsing SSE data: ${parseError.message}`));
        }
      }
    });

    // Wait for the stream to end
    await new Promise((resolve, reject) => {
      response.data.on('end', resolve);
      response.data.on('error', reject);
    });

    spinner.succeed(chalk.green(` ┊ ✓ Chat sent to Agent ${service_id.slice(0, 20)}...`));
    await sleep(500);
    return fullResponse;
  } catch (err) {
    spinner.fail(chalk.red(` ┊ ✗ Chat failed: ${err.message}`));
    await sleep(500);
    if (retryCount < maxRetries - 1) {
      return chatWithAI(access_token, service_id, message, proxy, retryCount + 1);
    }
    throw err;
  } finally {
    spinner.stop();
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Submits a report of the AI interaction.
 * @param {string} aa_address The smart account address.
 * @param {string} service_id The ID of the AI agent service.
 * @param {string} message The user's input message.
 * @param {string} aiResponse The AI's response.
 * @param {string} access_token The access token.
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<string>} The report ID.
 * @throws {Error} If report submission fails after retries.
 */
async function submitReport(aa_address, service_id, message, aiResponse, access_token, proxy = null, retryCount = 0) {
  const maxRetries = 5;
  await clearConsoleLine();
  const spinner = ora({ text: chalk.cyan(` ┊ → Submitting Report${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}`), prefixText: '', spinner: 'bouncingBar', interval: 120 }).start();
  isSpinnerActive = true;

  try {
    let config = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${access_token}`,
        'User-Agent': randomUseragent.getRandom(),
      },
    };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    const payload = {
      address: aa_address,
      service_id,
      input: [{ type: "text/plain", value: message }],
      output: [{ type: "text/plain", value: aiResponse }],
    };
    const response = await axios.post('https://neo.prod.gokite.ai/v2/submit_receipt', payload, config);
    const reportId = response.data.data.id;

    if (!reportId) throw new Error('Invalid response: report ID missing');

    spinner.succeed(chalk.green(` ┊ ✓ Report Submitted: ID=${reportId}`));
    await sleep(500);
    return reportId;
  } catch (err) {
    if (retryCount < maxRetries - 1) {
      spinner.text = chalk.cyan(` ┊ → Submitting Report [Retry #${retryCount + 1}/${maxRetries}]`);
      await sleep(5000);
      return submitReport(aa_address, service_id, message, aiResponse, access_token, proxy, retryCount + 1);
    }
    spinner.fail(chalk.red(` ┊ ✗ Failed to submit Report: ${err.message}`));
    await sleep(500);
    throw err;
  } finally {
    spinner.stop();
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

let transactionHashCache = []; // Cache for transaction hashes

/**
 * Retrieves the transaction hash (inference result) for a given report ID.
 * @param {string} reportId The report ID.
 * @param {string} access_token The access token.
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<string>} The transaction hash.
 * @throws {Error} If tx_hash is not found after retries.
 */
async function getInference(reportId, access_token, proxy = null, retryCount = 0) {
  const maxRetries = 5;
  await clearConsoleLine();
  const spinner = ora({ text: chalk.cyan(` ┊ → Fetching Tx Hash${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}`), prefixText: '', spinner: 'bouncingBar', interval: 120 }).start();
  isSpinnerActive = true;
  try {
    let config = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${access_token}`,
        'User-Agent': randomUseragent.getRandom(),
      },
    };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }
    const response = await axios.get(`https://neo.prod.gokite.ai/v1/inference?id=${reportId}`, config);
    const txHash = response.data.data.tx_hash;
    if (!txHash) {
      if (retryCount < maxRetries - 1) {
        spinner.text = chalk.cyan(` ┊ → Fetching Tx Hash [Retry #${retryCount + 1}/${maxRetries}]`);
        await sleep(20000); // Increased sleep for potentially slow inference propagation
        return getInference(reportId, access_token, proxy, retryCount + 1);
      }
      throw new Error('tx_hash not found after all retries');
    }
    spinner.succeed(chalk.green(` ┊ ✓ Tx hash received: ${txHash}`));
    await sleep(500);
    return txHash;
  } catch (err) {
    if (retryCount < maxRetries - 1) {
      spinner.text = chalk.cyan(` ┊ → Fetching Tx Hash [Retry #${retryCount + 1}/${maxRetries}]`);
      await sleep(20000); // Increased sleep for potentially slow inference propagation
      return getInference(reportId, access_token, proxy, retryCount + 1);
    }
    spinner.fail(chalk.red(` ┊ ✗ Failed to fetch Tx Hash: ${err.message}`));
    await sleep(500);
    throw err;
  } finally {
    spinner.stop();
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Retrieves a random transaction hash from a public RPC.
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<string>} A random transaction hash.
 * @throws {Error} If transaction hashes cannot be retrieved after retries.
 */
async function getRandomTransactionHash(proxy = null, retryCount = 0) {
  const maxRetries = 3;
  const RPC_URL = 'https://nodes.pancakeswap.info/'; // Public RPC for fetching transaction hashes

  if (transactionHashCache.length > 0) {
    const randomIndex = crypto.randomInt(0, transactionHashCache.length);
    return transactionHashCache[randomIndex];
  }

  await clearConsoleLine();
  const spinner = ora({ text: chalk.cyan(` ┊ → Fetching transaction hash from RPC${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}...`), prefixText: '', spinner: 'bouncingBar', interval: 120 }).start();
  isSpinnerActive = true;

  try {
    let config = { headers: { 'Content-Type': 'application/json', 'User-Agent': randomUseragent.getRandom() } };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    const payload = {
      jsonrpc: '2.0',
      id: 1,
      method: 'eth_getBlockByNumber',
      params: ['latest', true], // Get latest block with full transaction details
    };
    const response = await axios.post(RPC_URL, payload, config);
    const transactions = response.data.result?.transactions;

    if (!transactions || transactions.length === 0) throw new Error('No transactions found in latest block');

    // Cache up to 50 transaction hashes
    transactionHashCache = transactions.map(tx => tx.hash).slice(0, 50);
    const randomIndex = crypto.randomInt(0, transactionHashCache.length);

    spinner.succeed(chalk.green(` ┊ ✓ Transaction hash received`));
    await sleep(500);
    return transactionHashCache[randomIndex];
  } catch (err) {
    if (retryCount < maxRetries - 1) {
      spinner.text = chalk.cyan(` ┊ → Fetching transaction hash from RPC [Retry #${retryCount + 1}/${maxRetries}]`);
      await sleep(5000);
      return getRandomTransactionHash(proxy, retryCount + 1);
    }
    spinner.fail(chalk.red(` ✗ Failed to fetch transaction hash: ${err.message}`));
    await sleep(500);
    // Fallback to a dummy hash if all retries fail
    return '0x0000000000000000000000000000000000000000000000000000000000000000';
  } finally {
    spinner.stop();
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Retrieves wallet information (username, rank, XP points).
 * @param {string} access_token The access token.
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<object>} Wallet information.
 * @throws {Error} If wallet info retrieval fails after retries.
 */
async function getWalletInfo(access_token, proxy = null, retryCount = 0) {
  const maxRetries = 5;
  await clearConsoleLine();
  const spinner = ora({ text: chalk.cyan(` ┊ → Fetching wallet info${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}`), prefixText: '', spinner: 'bouncingBar', interval: 120 }).start();
  isSpinnerActive = true;

  try {
    let config = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${access_token}`,
        'User-Agent': randomUseragent.getRandom(),
      },
    };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    const response = await axios.get('https://ozone-point-system.prod.gokite.ai/leaderboard/me', config);
    const { username, rank, totalXpPoints } = response.data.data;

    if (!username || rank === undefined || totalXpPoints === undefined) {
      throw new Error('Invalid response: username, rank, or totalXpPoints missing');
    }

    spinner.succeed(chalk.green(` ┊ ✓ Wallet info received: ${username.slice(0, 8)}...`));
    await sleep(500);
    return { username, rank, totalXpPoints };
  } catch (err) {
    if (retryCount < maxRetries - 1) {
      spinner.text = chalk.cyan(` ┊ → Fetching wallet info [Retry #${retryCount + 1}/${maxRetries}]`);
      await sleep(5000);
      return getWalletInfo(access_token, proxy, retryCount + 1);
    }
    spinner.fail(chalk.red(` ┊ ✗ Failed to fetch wallet info: ${err.message}`));
    await sleep(500);
    throw err;
  } finally {
    spinner.stop();
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Creates a daily quiz.
 * @param {string} eoa The EOA address.
 * @param {string} access_token The access token.
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<string>} The quiz ID.
 * @throws {Error} If quiz creation fails after retries.
 */
async function createQuiz(eoa, access_token, proxy = null, retryCount = 0) {
  const maxRetries = 5;
  await clearConsoleLine();
  const spinner = ora({ text: chalk.cyan(` ┊ → Creating daily quiz${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}`), prefixText: '', spinner: 'bouncingBar', interval: 120 }).start();
  isSpinnerActive = true;

  try {
    let config = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${access_token}`,
        'User-Agent': randomUseragent.getRandom(),
      },
    };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    const today = moment().tz('Asia/Jakarta').format('YYYY-MM-DD');
    const payload = {
      title: `daily_quiz_${today}`,
      num: 1, // Number of questions in the quiz
      eoa,
    };
    const response = await axios.post('https://neo.prod.gokite.ai/v2/quiz/create', payload, config);
    const quiz_id = response.data.data.quiz_id;

    if (!quiz_id) throw new Error('Invalid response: quiz_id missing');

    spinner.succeed(chalk.green(` ┊ ✓ Quiz Created: quiz_id=${quiz_id}`));
    await sleep(500);
    return quiz_id;
  } catch (err) {
    if (retryCount < maxRetries - 1) {
      spinner.text = chalk.cyan(` ┊ → Creating daily quiz [Retry #${retryCount + 1}/${maxRetries}]`);
      await sleep(5000);
      return createQuiz(eoa, access_token, proxy, retryCount + 1);
    }
    spinner.fail(chalk.red(` ┊ ✗ Failed to create daily quiz: ${err.message}`));
    await sleep(500);
    throw err;
  } finally {
    spinner.stop();
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Retrieves the quiz question and its answer.
 * @param {string} quiz_id The ID of the quiz.
 * @param {string} eoa The EOA address.
 * @param {string} access_token The access token.
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<object>} Quiz details including question and answer.
 * @throws {Error} If quiz data retrieval fails after retries.
 */
async function getQuiz(quiz_id, eoa, access_token, proxy = null, retryCount = 0) {
  const maxRetries = 5;
  await clearConsoleLine();
  const spinner = ora({ text: chalk.cyan(` ┊ → Fetching quiz answer${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}`), prefixText: '', spinner: 'bouncingBar', interval: 120 }).start();
  isSpinnerActive = true;

  try {
    let config = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${access_token}`,
        'User-Agent': randomUseragent.getRandom(),
      },
    };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    const response = await axios.get(`https://neo.prod.gokite.ai/v2/quiz/get?id=${quiz_id}&eoa=${eoa}`, config);
    const quizData = response.data.data;

    if (!quizData.quiz || !quizData.question || quizData.question.length === 0) {
      throw new Error('Invalid response: quiz or question data missing');
    }

    const question = quizData.question[0];
    const quizDetails = {
      quiz_id: quizData.quiz.quiz_id,
      question_id: question.question_id,
      content: question.content,
      answer: question.answer,
    };

    spinner.succeed(chalk.green(` ┊ ✓ Answer Received: ${question.answer}`));
    await sleep(500);
    console.log(chalk.grey(` ┊ │    ╰┈➤  Question: ${question.content}`));
    return quizDetails;
  } catch (err) {
    if (retryCount < maxRetries - 1) {
      spinner.text = chalk.cyan(` ┊ → Fetching quiz answer [Retry #${retryCount + 1}/${maxRetries}]`);
      await sleep(5000);
      return getQuiz(quiz_id, eoa, access_token, proxy, retryCount + 1);
    }
    spinner.fail(chalk.red(` ┊ ✗ Failed to fetch quiz answer: ${err.message}`));
    await sleep(500);
    throw err;
  } finally {
    spinner.stop();
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Submits the answer to a quiz.
 * @param {string} quiz_id The ID of the quiz.
 * @param {string} question_id The ID of the question.
 * @param {string} answer The answer to submit.
 * @param {string} eoa The EOA address.
 * @param {string} access_token The access token.
 * @param {string | null} proxy The proxy string to use.
 * @param {number} retryCount Current retry attempt.
 * @returns {Promise<object>} The quiz submission result.
 * @throws {Error} If quiz submission fails after retries.
 */
async function submitQuiz(quiz_id, question_id, answer, eoa, access_token, proxy = null, retryCount = 0) {
  const maxRetries = 5;
  await clearConsoleLine();
  const spinner = ora({ text: chalk.cyan(` ┊ → Submitting quiz answer${retryCount > 0 ? ` [Retry #${retryCount}/${maxRetries}]` : ''}`), prefixText: '', spinner: 'bouncingBar', interval: 120 }).start();
  isSpinnerActive = true;

  try {
    let config = {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${access_token}`,
        'User-Agent': randomUseragent.getRandom(),
      },
    };
    const agent = createProxyAgent(proxy);
    if (agent) {
      config.httpAgent = agent;
      config.httpsAgent = agent;
    }

    const payload = {
      quiz_id,
      question_id,
      answer,
      finish: true, // Mark quiz as finished
      eoa,
    };
    const response = await axios.post('https://neo.prod.gokite.ai/v2/quiz/submit', payload, config);
    const result = response.data.data.result;

    if (!result) throw new Error('Invalid response: result missing');

    spinner.succeed(chalk.green(` ┊ ✓ Answer Correct, Daily Quiz Completed`));
    await sleep(500);
    return result;
  } catch (err) {
    if (retryCount < maxRetries - 1) {
      spinner.text = chalk.cyan(` ┊ → Submitting quiz answer [Retry #${retryCount + 1}/${maxRetries}]`);
      await sleep(5000);
      return submitQuiz(quiz_id, question_id, answer, eoa, access_token, proxy, retryCount + 1);
    }
    spinner.fail(chalk.red(` ┊ ✗ Failed to submit quiz answer: ${err.message}`));
    await sleep(500);
    throw err;
  } finally {
    spinner.stop();
    isSpinnerActive = false;
    await clearConsoleLine();
  }
}

/**
 * Selects an AI agent based on a weighted random distribution,
 * prioritizing agents that have been used less.
 * @param {string[]} agentNames Array of agent names.
 * @param {string[]} usedAgents Array of agents already used in the current cycle.
 * @returns {string} The selected agent name.
 */
function selectAgent(agentNames, usedAgents) {
  const weights = agentNames.map(agent => {
    const count = usedAgents.filter(a => a === agent).length;
    return 1 / (1 + count); // Less used agents get higher weight
  });
  const totalWeight = weights.reduce((sum, w) => sum + w, 0);
  
  let cumulative = 0; // Initialize cumulative HERE
  const normalizedWeights = weights.map(w => {
    cumulative += w;
    return cumulative;
  });

  const random = crypto.randomInt(0, 1000) / 1000; // Random float between 0 and 1

  for (let i = 0; i < normalizedWeights.length; i++) {
    if (random <= normalizedWeights[i]) return agentNames[i];
  }
  return agentNames[agentNames.length - 1]; // Fallback, should not be reached
}

let lastCycleEndTime = null; // Stores the timestamp of the last cycle's completion

/**
 * Starts a countdown timer until the next scheduled run.
 * @param {moment.Moment} nextRunTime The moment object for the next run time.
 */
function startCountdown(nextRunTime) {
  const countdownInterval = setInterval(() => {
    if (isSpinnerActive) return; // Pause countdown display if a spinner is active
    const now = moment();
    const timeLeft = moment.duration(nextRunTime.diff(now));

    if (timeLeft.asSeconds() <= 0) {
      clearInterval(countdownInterval);
      return;
    }
    clearConsoleLine();
    const hours = Math.floor(timeLeft.asHours()).toString().padStart(2, '0');
    const minutes = Math.floor(timeLeft.asMinutes() % 60).toString().padStart(2, '0');
    const seconds = Math.floor(timeLeft.asSeconds() % 60).toString().padStart(2, '0');
    process.stdout.write(chalk.cyan(` ┊ ⏳ Waiting for next cycle: ${hours}:${minutes}:${seconds}\r`));
  }, 1000);
}

/**
 * Processes all accounts: authenticates, chats with AI, completes daily quizzes, and fetches wallet info.
 * @param {Array<{address: string, privateKey: string}>} accounts Array of account objects.
 * @param {string[]} professorMessages Messages for Professor AI.
 * @param {string[]} cryptoBuddyMessages Messages for Crypto Buddy AI.
 * @param {Array<string | null>} accountProxies Array of proxy strings corresponding to each account.
 * @param {number} chatCount Number of chats to perform per account.
 * @param {boolean} noType If true, disables typing animation for AI responses.
 */
async function processAccounts(accounts, professorMessages, cryptoBuddyMessages, accountProxies, chatCount, noType) {
  let successCount = 0;
  let failCount = 0;

  // Define AI agent IDs
  const aiAgents = {
    "Professor": "deployment_KiMLvUiTydioiHm7PWZ12zJU",
    "Crypto Buddy": "deployment_ByVHjMD6eDb9AdekRIbyuz14",
    "Sherlock": "deployment_OX7sn2D0WvxGUGK8CTqsU5VJ"
  };
  const agentNames = ["Professor", "Crypto Buddy", "Sherlock"];

  for (let i = 0; i < accounts.length; i++) {
    const account = accounts[i];
    const proxy = accountProxies[i];
    const shortAddress = `${account.address.slice(0, 8)}...${account.address.slice(-6)}`;
    const usedAgents = []; // Track agents used in the current account's cycle

    displayHeader(`═════[ Account ${i + 1}/${accounts.length} | ${shortAddress} @ ${getTimestamp()} ]═════`, chalk.blue);
    console.log(chalk.cyan(` ┊ ${proxy ? `Using proxy: ${proxy}` : 'Not using proxy'}`));

    let accountSuccessful = false; // Flag to track if at least one chat was successful for the account
    try {
      const { access_token, aa_address } = await authenticate(account.address, account.privateKey, proxy);
      const profile = await login(account.address, aa_address, access_token, proxy);

      console.log(chalk.magentaBright(' ┊ ┌── Chat Process ──'));
      let successfulChatsForAccount = 0;
      let failedChatsForAccount = 0;

      for (let j = 0; j < chatCount; j++) {
        console.log(chalk.yellow(` ┊ ├─ Chat ${createProgressBar(j + 1, chatCount)} ──`));
        const selectedAgent = selectAgent(agentNames, usedAgents);
        usedAgents.push(selectedAgent); // Add selected agent to used list for this account
        const service_id = aiAgents[selectedAgent];
        let message;

        // Select message based on agent type
        if (selectedAgent === "Sherlock") {
          const hash = await getRandomTransactionHash(proxy);
          message = `What do you think of this transaction? ${hash}`;
        } else if (selectedAgent === "Professor") {
          if (!professorMessages.length) throw new Error('No Professor messages available');
          message = professorMessages[crypto.randomInt(0, professorMessages.length)].replace(/\r/g, '');
        } else { // Crypto Buddy
          if (!cryptoBuddyMessages.length) throw new Error('No Crypto Buddy messages available');
          message = cryptoBuddyMessages[crypto.randomInt(0, cryptoBuddyMessages.length)].replace(/\r/g, '');
        }

        console.log(`${chalk.white(' ┊ │ Using Agent [ ')}${chalk.green(selectedAgent)}${chalk.white(' ] - Message: ')}${chalk.yellow(message)}`);

        try {
          const response = await chatWithAI(access_token, service_id, message, proxy);
          await typeText(response, chalk.green, noType);
          const reportId = await submitReport(aa_address, service_id, message, response, access_token, proxy);
          await getInference(reportId, access_token, proxy);
          successfulChatsForAccount++;
          console.log(chalk.yellow(' ┊ └──'));
        } catch (chatErr) {
          console.log(chalk.red(` ┊ ✗ Chat ${j + 1} failed: ${chatErr.message}`));
          failedChatsForAccount++;
          console.log(chalk.yellow(' ┊ └──'));
        }
        await sleep(8000); // Delay between chats
      }
      console.log(chalk.yellow(' ┊ └──'));

      console.log(chalk.magentaBright(' ┊ ┌── Daily Quiz Process ──'));
      try {
        const quiz_id = await createQuiz(account.address, access_token, proxy);
        const quizDetails = await getQuiz(quiz_id, account.address, access_token, proxy);
        await submitQuiz(quiz_id, quizDetails.question_id, quizDetails.answer, account.address, access_token, proxy);
      } catch (quizErr) {
        console.log(chalk.red(` ┊ ✗ Failed to complete daily quiz: ${quizErr.message}`));
      }
      console.log(chalk.yellow(' ┊ └──'));

      try {
        const walletInfo = await getWalletInfo(access_token, proxy);
        const agentCounts = agentNames.reduce((counts, agent) => {
          counts[agent] = usedAgents.filter(a => a === agent).length;
          return counts;
        }, {});
        console.log(chalk.yellow(' ┊ ┌── User Information ──'));
        console.log(chalk.white(` ┊ │ Username: ${walletInfo.username.slice(0, 8)}...`));
        console.log(chalk.white(` ┊ │ Rank: ${walletInfo.rank}`));
        console.log(chalk.white(` ┊ │ Total XP Points: ${walletInfo.totalXpPoints}`));
        agentNames.forEach(agent => {
          console.log(chalk.white(` ┊ │ Agent ${agent}: ${agentCounts[agent] || 0}`));
        });
        console.log(chalk.yellow(' ┊ └──'));
      } catch (walletErr) {
        console.log(chalk.red(` ┊ ✗ Failed to get wallet info: ${walletErr.message}`));
      }

      if (successfulChatsForAccount > 0) {
        successCount++;
        accountSuccessful = true;
      } else {
        failCount++;
      }
    } catch (err) {
      console.log(chalk.red(` ┊ ✗ Error processing account ${shortAddress}: ${err.message}`));
      if (!accountSuccessful) { // Only increment failCount if no successful chat happened for this account
        failCount++;
      }
    }

    console.log(chalk.gray(' ┊ ══════════════════════════════════════'));
  }

  lastCycleEndTime = moment();
  displayHeader(`═════[ Finished @ ${getTimestamp()} ]═════`, chalk.blue, false);
  console.log(chalk.gray(` ┊ ✅ ${successCount} accounts successful, ❌ ${failCount} accounts failed`));
  const nextRunTime = moment().add(24, 'hours');
  startCountdown(nextRunTime);
}

let isProcessing = false; // Flag to prevent multiple concurrent runs

/**
 * Schedules the next run of the account processing.
 * @param {Array<{address: string, privateKey: string}>} accounts Array of account objects.
 * @param {string[]} professorMessages Messages for Professor AI.
 * @param {string[]} cryptoBuddyMessages Messages for Crypto Buddy AI.
 * @param {Array<string | null>} accountProxies Array of proxy strings.
 * @param {number} chatCount Number of chats per account.
 * @param {boolean} noType If true, disables typing animation.
 */
function scheduleNextRun(accounts, professorMessages, cryptoBuddyMessages, accountProxies, chatCount, noType) {
  const delay = 24 * 60 * 60 * 1000; // 24 hours in milliseconds
  console.log(chalk.cyan(` ┊ ⏰ Process will repeat every 24 hours...`));
  setInterval(async () => {
    if (isProcessing || isSpinnerActive) return; // Don't run if already processing or spinner is active
    try {
      isProcessing = true;
      const nextRunTime = moment().add(24, 'hours');
      await processAccounts(accounts, professorMessages, cryptoBuddyMessages, accountProxies, chatCount, noType);
      startCountdown(nextRunTime);
    } catch (err) {
      console.log(chalk.red(` ✗ Error during cycle: ${err.message}`));
    } finally {
      isProcessing = false;
    }
  }, delay);
}

/**
 * Main function to initialize the bot.
 */
async function main() {
  console.log('\n');
  displayBanner();
  const noType = process.argv.includes('--no-type'); // Check for --no-type argument

  let accounts = [];
  // --- SECURE PRIVATE KEY LOADING ---
  // Instead of accounts.txt, load from PRIVATE_KEYS_LIST environment variable.
  const privateKeysList = process.env.PRIVATE_KEYS_LIST;

  if (!privateKeysList) {
    console.error(chalk.red("Error: PRIVATE_KEYS_LIST environment variable is not set."));
    console.error(chalk.red("Please create a .env file in the project root and add:"));
    console.error(chalk.red("PRIVATE_KEYS_LIST=\"key1,key2,key3\" (comma-separated private keys)"));
    console.error(chalk.red("Remember to NEVER commit your .env file to version control!"));
    rl.close();
    return;
  }

  const rawPrivateKeys = privateKeysList.split(',').map(key => key.trim()).filter(key => key !== '');

  if (rawPrivateKeys.length === 0) {
    console.error(chalk.red("Error: PRIVATE_KEYS_LIST environment variable is empty or contains no valid keys."));
    rl.close();
    return;
  }

  for (let i = 0; i < rawPrivateKeys.length; i++) {
    const privateKey = rawPrivateKeys[i];
    if (!isValidPrivateKey(privateKey)) {
      console.error(chalk.red(`✗ Private key at index ${i} is invalid: ${privateKey}. Must be a 64-character hexadecimal string.`));
      rl.close();
      return;
    }
    try {
      const wallet = new ethers.Wallet(privateKey.startsWith('0x') ? privateKey : `0x${privateKey}`);
      accounts.push({ address: wallet.address, privateKey });
    } catch (e) {
      console.error(chalk.red(`✗ Could not create wallet from private key at index ${i}: ${e.message}`));
      rl.close();
      return;
    }
  }

  if (accounts.length === 0) {
    console.log(chalk.red('✗ No valid accounts loaded from PRIVATE_KEYS_LIST!'));
    rl.close();
    return;
  }

  // Load messages for AI agents from files
  let professorMessages = [];
  let cryptoBuddyMessages = [];
  try {
    const professorMsgData = await fs.readFile('pesan_professor.txt', 'utf8');
    professorMessages = professorMsgData.split('\n').filter(line => line.trim() !== '').map(line => line.replace(/\r/g, ''));
    const cryptoBuddyMsgData = await fs.readFile('pesan_cryptobuddy.txt', 'utf8');
    cryptoBuddyMessages = cryptoBuddyMsgData.split('\n').filter(line => line.trim() !== '').map(line => line.replace(/\r/g, ''));
  } catch (err) {
    console.log(chalk.red('✗ Message files (pesan_professor.txt or pesan_cryptobuddy.txt) not found or empty!'));
    rl.close();
    return;
  }

  if (professorMessages.length === 0) {
    console.log(chalk.red('✗ File pesan_professor.txt is empty!'));
    rl.close();
    return;
  }
  if (cryptoBuddyMessages.length === 0) {
    console.log(chalk.red('✗ File pesan_cryptobuddy.txt is empty!'));
    rl.close();
    return;
  }

  let chatCount;
  while (true) {
    const input = await promptUser('Enter number of chats per account: ');
    chatCount = parseInt(input, 10);
    if (!isNaN(chatCount) && chatCount > 0) break;
    console.log(chalk.red('✗ Please enter a valid number!'));
  }

  let useProxy;
  while (true) {
    const input = await promptUser('Use proxy? (y/n) ');
    if (input.toLowerCase() === 'y' || input.toLowerCase() === 'n') {
      useProxy = input.toLowerCase() === 'y';
      break;
    }
    console.log(chalk.red('✗ Please enter "y" or "n"!'));
  }

  let proxies = [];
  if (useProxy) {
    try {
      const proxyData = await fs.readFile('proxy.txt', 'utf8');
      proxies = proxyData.split('\n').filter(line => line.trim() !== '');
      if (proxies.length === 0) {
        console.log(chalk.yellow('✗ File proxy.txt is empty. Continuing without proxy.'));
      }
    } catch (err) {
      console.log(chalk.yellow('✗ File proxy.txt not found. Continuing without proxy.'));
    }
  }

  // Map proxies to accounts in a round-robin fashion
  const accountProxies = accounts.map((_, index) => proxies.length > 0 ? proxies[index % proxies.length] : null);

  console.log(chalk.cyan(` ┊ ⏰ Starting process for ${accounts.length} accounts...`));
  await processAccounts(accounts, professorMessages, cryptoBuddyMessages, accountProxies, chatCount, noType);
  scheduleNextRun(accounts, professorMessages, cryptoBuddyMessages, accountProxies, chatCount, noType);
  rl.close();
}

main();