import assert from 'node:assert/strict';
import {bindingFor, validateRequest} from './protocol.mjs';
import { createHash, createPublicKey, verify } from 'node:crypto';
import fs from 'node:fs';
import { compile } from '../vendor/nucleovm/compact-js.mjs';
import { payments, Transaction, script, networks } from 'bitcoinjs-lib';

export const source = fs.readFileSync(new URL('../src/litecoin-p2wpkh-v2.js', import.meta.url), 'utf8');
export const publicFunctions=['getPublicKey','signHash'];
export const binarySource=source+'\n'+fs.readFileSync(new URL('../src/njbc-exports.js',import.meta.url),'utf8');
export const bytecode=compile(binarySource,{publicFunctions}).toString('hex');
export const appletID = network => {litecoinNetwork(network);return `org.tripylon.litecoin.p2wpkh.v1/${network}`;};
export function expectedBinding(network='testnet',format='js'){
  if(!['js','njbc'].includes(format))throw new Error('Choose js or njbc');
  return bindingFor(appletID(network),format==='js'?Buffer.from(source):Buffer.from(bytecode,'hex'),format);
}
export const appletRequest = (index, hash = '', network = 'testnet', format = 'js') => {
  if (!Number.isInteger(index) || index < 0 || index > 2147483647 || typeof hash!=='string' || (hash && !/^[a-f0-9]{64}$/i.test(hash))) throw new Error('Invalid key index or signing hash');
  expectedBinding(network,format);
  return validateRequest({namespace:appletID(network),...(format==='js'?{code:source}:{format:'njbc',bytecode}),invoke:hash ? {name:'signHash',params:{keyIndex:index,hash:hash.toLowerCase()}} : {name:'getPublicKey',params:{keyIndex:index}}});
};
export function parseVM(response, network = 'testnet',format='js') {
  if (response.vmProtocol !== 2 || response.appletBinding !== expectedBinding(network,format)) throw new Error('Code-bound applet protocol 2 / firmware 0.0.6 required');
  if (response.isError) throw new Error(`Applet failed: ${response.result}`);
  const value = JSON.parse(response.result);
  if (value.applet !== 'litecoin-p2wpkh-v2' || !/^(02|03)[a-f0-9]{64}$/i.test(value.publicKey)) throw new Error('Unexpected applet result');
  const allowed = ['applet', 'publicKey', ...(value.signatureDER ? ['signatureDER', 'hashForSign'] : [])].sort();
  assert.deepEqual(Object.keys(value).sort(), allowed, 'Applet must return public information only');
  return value;
}
export function litecoinNetwork(network) {
  if (!['mainnet', 'testnet'].includes(network)) throw new Error('Choose mainnet or testnet');
  return { ...(network === 'mainnet' ? networks.bitcoin : networks.testnet),
    messagePrefix: '\x19Litecoin Signed Message:\n', bech32: network === 'mainnet' ? 'ltc' : 'tltc',
    pubKeyHash: network === 'mainnet' ? 48 : 111, scriptHash: network === 'mainnet' ? 50 : 58, wif: network === 'mainnet' ? 176 : 239 };
}
const sha = bytes => createHash('sha256').update(bytes).digest();
const doubleSha = bytes => sha(sha(bytes));
const u32 = value => { const out = Buffer.alloc(4); out.writeUInt32LE(value); return out; };
const u64 = value => { const out = Buffer.alloc(8); out.writeBigUInt64LE(value); return out; };

export function offlineTransfer(publicKeyHex, network = 'testnet') {
  const publicKey = Buffer.from(publicKeyHex, 'hex');
  const payment = payments.p2wpkh({ pubkey: publicKey, network: litecoinNetwork(network) });
  // This previous transaction is invented locally: it is not a real funded UTXO.
  const previous = new Transaction(); previous.version = 2;
  previous.addInput(sha(Buffer.from('TriPylon Litecoin VM synthetic offline UTXO v1')), 0);
  previous.addOutput(payment.output, 100000n);
  const tx = new Transaction(); tx.version = 2;
  tx.addInput(previous.getHash(), 0, 0xfffffffd);
  tx.addOutput(payment.output, 90000n);
  const scriptCode = Buffer.from(payments.p2pkh({ pubkey: publicKey }).output);
  // Independently assemble the BIP143 preimage as well as using bitcoinjs-lib.
  const preimage = Buffer.concat([u32(2), doubleSha(Buffer.concat([previous.getHash(), u32(0)])),
    doubleSha(u32(0xfffffffd)), previous.getHash(), u32(0), Buffer.from([scriptCode.length]), scriptCode,
    u64(100000n), u32(0xfffffffd), doubleSha(Buffer.concat([u64(90000n), Buffer.from([payment.output.length]), payment.output])), u32(0), u32(1)]);
  const hash = doubleSha(preimage).toString('hex');
  assert.equal(Buffer.from(tx.hashForWitnessV0(0, scriptCode, 100000n, Transaction.SIGHASH_ALL)).toString('hex'), hash);
  return { tx, address: payment.address, hash, preimage, publicKey };
}

export function verifyOfflineTransfer(plan, response) {
  assert.equal(response.publicKey.toLowerCase(), plan.publicKey.toString('hex'));
  assert.equal(response.hashForSign, plan.hash);
  assert.match(response.signatureDER, /^(?:[0-9a-f]{2})+$/i);
  const der = Buffer.from(response.signatureDER, 'hex');
  const decoded = script.signature.decode(Buffer.concat([der, Buffer.from([1])]));
  assert.equal(decoded.hashType, Transaction.SIGHASH_ALL);
  const spki = Buffer.concat([Buffer.from('3036301006072a8648ce3d020106052b8104000a032200', 'hex'), plan.publicKey]);
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  // ECDSA checks SHA256(SHA256(preimage)), matching the Litecoin BIP143 digest.
  assert.equal(verify('sha256', sha(plan.preimage), key, der), true, 'OpenSSL rejected the device signature');
  const altered = Buffer.from(plan.preimage); altered[altered.length - 9] ^= 1;
  assert.equal(verify('sha256', sha(altered), key, der), false, 'Changed transaction must be rejected');
  plan.tx.setWitness(0, [Buffer.concat([der, Buffer.from([1])]), plan.publicKey]);
  const tx = Transaction.fromHex(plan.tx.toHex());
  assert.equal(tx.ins[0].witness[0].at(-1), 1);
  assert.deepEqual(Buffer.from(tx.ins[0].witness[1]), plan.publicKey);
  return { address: plan.address, signingHash: plan.hash, txid: tx.getId(), virtualSize: tx.virtualSize(),
    rawTransaction: tx.toHex(), syntheticInput: true, transactionBroadcast: false, signatureValid: true, changedTransactionRejected: true };
}
