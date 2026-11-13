import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {createHash,createPublicKey,verify} from 'node:crypto';
import {SigningKey} from 'ethers';
import {compile,decompile} from '../vendor/nucleovm/compact-js.mjs';
import {appletID,source,binarySource,publicFunctions,bytecode,appletRequest,expectedBinding,parseVM,offlineTransfer,verifyOfflineTransfer} from '../lib/applet.mjs';
import {bindingFor,validateRequest} from '../lib/protocol.mjs';
import {makeFixture,fixtureKey} from './fixture.mjs';
const compatibility=JSON.parse(fs.readFileSync(new URL('../compatibility.json',import.meta.url)));
test('source preserves existing JS identity and bytecode build is deterministic',()=>{
  assert.equal(createHash('sha256').update(source).digest('hex'),compatibility.legacySourceSha256);
  assert.equal(compile(binarySource,{publicFunctions}).toString('hex'),bytecode);
  assert.deepEqual(decompile(Buffer.from(bytecode,'hex')).publicFunctions,publicFunctions);
  assert.notEqual(expectedBinding('testnet','js'),expectedBinding('testnet','njbc'));
  assert.notEqual(bindingFor(appletID('testnet'),Buffer.from(source+'\n')),expectedBinding('testnet'));
});
for(const format of ['js','njbc']){
  test(format+': deterministic public keys, distinct indices/networks, public output only',()=>{
    const fixture=makeFixture(),request=appletRequest(0,'','testnet',format);
    const read=(index,network='testnet')=>parseVM(fixture.invoke(appletRequest(index,'',network,format)),network,format);
    const a=read(0);assert.deepEqual(a,read(0));assert.notEqual(a.publicKey,read(1).publicKey);
    assert.notEqual(a.publicKey,read(0,'mainnet').publicKey);
    const expected=fixtureKey(expectedBinding('testnet',format),0).key;
    assert.equal(a.publicKey,new SigningKey(expected).compressedPublicKey.slice(2));
    assert.deepEqual(Object.keys(a).sort(),['applet','publicKey']);assert.equal(fixture.confirmations,0);
    assert.equal(validateRequest({...request,command:'factoryReset'}).command,undefined);
  });
  test(format+': compatible ECDSA signs Litecoin BIP143, rejects tampering and denied confirmation',()=>{
    const fixture=makeFixture(),get=appletRequest(0,'','testnet',format);
    const pub=parseVM(fixture.invoke(get),'testnet',format).publicKey,plan=offlineTransfer(pub);
    const req=appletRequest(0,plan.hash,'testnet',format),response=fixture.invoke(req),signed=parseVM(response,'testnet',format);
    assert.equal(verifyOfflineTransfer(plan,signed).signatureValid,true);assert.equal(fixture.confirmations,1);
    assert.equal(req.code,get.code);assert.equal(req.bytecode,get.bytecode);
    assert.throws(()=>makeFixture({confirm:false}).invoke(req),/confirmation denied/);
    assert.throws(()=>parseVM({...response,appletBinding:'00'.repeat(32)},'testnet',format));
    assert.throws(()=>parseVM({...response,result:JSON.stringify({...signed,privateKey:'leak'})},'testnet',format));
    const wrongKey=Buffer.from(new SigningKey('0x'+'01'.repeat(32)).compressedPublicKey.slice(2),'hex');
    const spki=Buffer.concat([Buffer.from('3036301006072a8648ce3d020106052b8104000a032200','hex'),wrongKey]);
    assert.equal(verify('sha256',createHash('sha256').update(plan.preimage).digest(),createPublicKey({key:spki,format:'der',type:'spki'}),Buffer.from(signed.signatureDER,'hex')),false);
  });
}
test('invalid parameters, hash, function and networks fail before transport',()=>{
  for(const n of [-1,1.5,NaN,2147483648])assert.throws(()=>appletRequest(n));
  for(const h of ['aa','z'.repeat(64),null,42])assert.throws(()=>appletRequest(0,h));
  assert.throws(()=>appletRequest(0,'','nile'));assert.throws(()=>appletRequest(0,'','testnet','invalid'));
  const request=appletRequest(0);
  for(const name of ['appletNonce8','constructor','signHash();'])assert.throws(()=>validateRequest({...request,invoke:{name,params:{keyIndex:0}}}));
  assert.throws(()=>validateRequest({...request,invoke:{name:'signHash',params:{keyIndex:0}}}));
});
test('NJBC artifact is well formed and export metadata cannot be silently corrupted',()=>{
  const binary=Buffer.from(bytecode,'hex');assert.equal(binary.subarray(0,5).toString('hex'),'4e4a424302');
  assert.throws(()=>decompile(binary.subarray(0,-1)));assert.throws(()=>decompile(Buffer.concat([binary,Buffer.of(0)])));
});
