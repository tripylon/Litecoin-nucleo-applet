// Public deterministic fixture only. No wallet connection, seed access or OS code.
import {createHash,createHmac} from 'node:crypto';
import vm from 'node:vm';
import {SigningKey} from 'ethers';
import {script} from 'bitcoinjs-lib';
import {decompile} from '../vendor/nucleovm/compact-js.mjs';
import {bindingFor,validateRequest} from '../lib/protocol.mjs';

const hmac=(key,...data)=>{const h=createHmac('sha256',key);data.forEach(d=>h.update(d));return h.digest();};
export function fixtureKey(binding,index){
  // Deliberately a test-only derivation, not an implementation of wallet secrets.
  const nonce=createHash('sha256').update('Litecoin applet public test nonce\0').update(Buffer.from(binding,'hex')).digest();
  const suffix=Buffer.alloc(8);suffix.writeUInt32BE(index);
  for(let counter=0;counter<1024;counter++){
    suffix.writeUInt32BE(counter,4);
    const key=hmac(nonce,'Litecoin applet public fixture key\0',suffix);
    try{new SigningKey(key);return {nonce,key};}catch{/* Deterministic rejection sampling. */}
  }
  throw new Error('No valid scalar');
}
export function makeFixture({confirm=true}={}){
  let confirmations=0;
  const invoke=request=>{
    validateRequest(request);
    const binary=request.format==='njbc';
    const binding=bindingFor(request.namespace,binary?Buffer.from(request.bytecode,'hex'):Buffer.from(request.code),binary?'njbc':'js');
    const code=binary?decompile(Buffer.from(request.bytecode,'hex')):null;
    if(binary&&!code.publicFunctions.includes(request.invoke.name))throw new Error('Not a public export');
    const nonce=fixtureKey(binding,0).nonce;
    const context=vm.createContext({
      appletNonce8:()=>({hex:nonce.toString('hex')}),
      deriveSecp256k1Key:(hex,index)=>{
        if(hex!==nonce.toString('hex')||!Number.isInteger(index)||index<0||index>2147483647)throw new Error('Invalid derivation');
        return fixtureKey(binding,index).key.toString('hex');
      },
      secp256k1PublicKey:key=>new SigningKey('0x'+key).compressedPublicKey.slice(2),
      secp256k1SignHash:(hash,key)=>{
        if(!/^[a-f\d]{64}$/i.test(hash))throw new Error('Invalid digest');
        confirmations++;
        if(!confirm)throw new Error('Physical confirmation denied (fixture)');
        const signer=new SigningKey('0x'+key),signature=signer.sign('0x'+hash);
        const compact=Buffer.concat([Buffer.from(signature.r.slice(2),'hex'),Buffer.from(signature.s.slice(2),'hex')]);
        const der=Buffer.from(script.signature.encode(compact,1)).subarray(0,-1).toString('hex');
        return {publicKey:signer.compressedPublicKey.slice(2),signatureDER:der};
      },
    });
    // Execute this repository's trusted applet only. Node vm is not a security sandbox.
    const call=binary?request.invoke.name:'applet.'+request.invoke.name;
    const result=vm.runInContext((binary?code.source:request.code)+'\n'+call+'('+JSON.stringify(request.invoke.params)+');',context,{timeout:1000});
    return {vmProtocol:2,appletBinding:binding,isError:false,result:JSON.stringify(result)};
  };
  return {invoke,get confirmations(){return confirmations;}};
}
