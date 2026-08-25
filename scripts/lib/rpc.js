// Minimal JSON-RPC client for QRL 2.0 execution nodes over the global fetch.
//
// Covers what the toolchain scripts and contract tests need (qrl_call,
// qrl_sendTransaction, qrl_estimateGas, receipt polling, chain id, accounts,
// blocks). Both signing paths (the unlocked gqrl --dev account and locally
// signed Kurtosis transactions) end up reading receipts through this client,
// so callers see one receipt shape.

class JsonRpcError extends Error {
  constructor(method, error) {
    super(`${method}: ${error?.message || JSON.stringify(error)}`);
    this.name = 'JsonRpcError';
    this.code = error?.code;
    this.data = error?.data;
  }
}

const QUANTITY_FIELDS = new Set([
  'gas',
  'gasPrice',
  'value',
  'nonce',
  'maxFeePerGas',
  'maxPriorityFeePerGas',
]);

function toQuantity(value) {
  if (typeof value === 'string') {
    if (/^0x[0-9a-fA-F]+$/.test(value)) {
      return `0x${BigInt(value).toString(16)}`;
    }
    if (/^\d+$/.test(value)) {
      return `0x${BigInt(value).toString(16)}`;
    }
    throw new TypeError(`not a quantity: ${value}`);
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new TypeError(`not a quantity: ${value}`);
    }
    return `0x${value.toString(16)}`;
  }
  if (typeof value === 'bigint') {
    if (value < 0n) {
      throw new TypeError(`not a quantity: ${value}`);
    }
    return `0x${value.toString(16)}`;
  }
  throw new TypeError(`not a quantity: ${String(value)}`);
}

function fromQuantity(hex) {
  if (typeof hex === 'bigint') {
    return hex;
  }
  if (typeof hex === 'number') {
    return BigInt(hex);
  }
  if (typeof hex !== 'string' || !/^0x[0-9a-fA-F]+$/.test(hex)) {
    throw new TypeError(`not a hex quantity: ${String(hex)}`);
  }
  return BigInt(hex);
}

function formatTx(tx) {
  const out = {};
  for (const [key, value] of Object.entries(tx)) {
    if (value === undefined || value === null) continue;
    out[key] = QUANTITY_FIELDS.has(key) ? toQuantity(value) : value;
  }
  return out;
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

class RpcClient {
  constructor(url, options = {}) {
    if (!url) {
      throw new Error('RpcClient needs an RPC URL');
    }
    this.url = url;
    this.timeoutMs = options.timeoutMs ?? 30000;
    this.fetchImpl = options.fetchImpl || globalThis.fetch;
    if (typeof this.fetchImpl !== 'function') {
      throw new Error('global fetch is unavailable; Node 20 or newer is required');
    }
    this.nextId = 1;
  }

  async call(method, params = []) {
    const id = this.nextId++;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    let response;
    try {
      response = await this.fetchImpl(this.url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id, method, params }),
        signal: controller.signal,
      });
    } catch (error) {
      throw new Error(`${method}: request to ${this.url} failed (${error.message})`);
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      throw new Error(`${method}: HTTP ${response.status} from ${this.url}`);
    }
    const payload = await response.json();
    if (payload.error) {
      throw new JsonRpcError(method, payload.error);
    }
    return payload.result;
  }

  async chainId() {
    return Number(await this.call('qrl_chainId'));
  }

  async accounts() {
    return (await this.call('qrl_accounts')) || [];
  }

  async blockNumber() {
    return Number(await this.call('qrl_blockNumber'));
  }

  async getBlockByNumber(tag = 'latest', fullTransactions = false) {
    const block = typeof tag === 'string' ? tag : toQuantity(tag);
    return this.call('qrl_getBlockByNumber', [block, fullTransactions]);
  }

  async getBalance(address, block = 'latest') {
    return fromQuantity(await this.call('qrl_getBalance', [address, block]));
  }

  async getCode(address, block = 'latest') {
    return this.call('qrl_getCode', [address, block]);
  }

  async getTransactionCount(address, block = 'pending') {
    return Number(await this.call('qrl_getTransactionCount', [address, block]));
  }

  async gasPrice() {
    return fromQuantity(await this.call('qrl_gasPrice'));
  }

  async estimateGas(tx) {
    return fromQuantity(await this.call('qrl_estimateGas', [formatTx(tx)]));
  }

  async qrlCall(tx, block = 'latest') {
    return this.call('qrl_call', [formatTx(tx), block]);
  }

  async sendTransaction(tx) {
    return this.call('qrl_sendTransaction', [formatTx(tx)]);
  }

  async sendRawTransaction(raw) {
    return this.call('qrl_sendRawTransaction', [raw]);
  }

  async getTransactionReceipt(hash) {
    return this.call('qrl_getTransactionReceipt', [hash]);
  }

  async waitForReceipt(hash, options = {}) {
    const timeoutMs = options.timeoutMs ?? 120000;
    const pollMs = options.pollMs ?? 500;
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      const receipt = await this.getTransactionReceipt(hash);
      if (receipt) {
        return receipt;
      }
      if (Date.now() >= deadline) {
        throw new Error(`transaction ${hash} was not mined within ${timeoutMs} ms`);
      }
      await delay(pollMs);
    }
  }
}

module.exports = { JsonRpcError, RpcClient, formatTx, fromQuantity, toQuantity };
