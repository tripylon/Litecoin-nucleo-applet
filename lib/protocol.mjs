import {createHash} from 'node:crypto';

const u32=n=>{const b=Buffer.alloc(4);b.writeUInt32BE(n);return b;};
export function bindingFor(namespace,code,format='js'){
  if(!/^[a-zA-Z0-9./:_-]{1,96}$/.test(namespace)||!['js','njbc'].includes(format))throw new Error('Invalid applet identity');
  const id=Buffer.from(namespace),bytes=Buffer.from(code);
  if(!bytes.length||bytes.length>16384||format==='js'&&bytes.includes(0))throw new Error('Invalid code size/content');
  const domain=format==='js'?'TriPylon/applet-binding/v2\0':'TriPylon/applet-binding/njbc/v2\0';
  return createHash('sha256').update(domain).update(u32(id.length)).update(id).update(u32(bytes.length)).update(bytes).digest('hex');
}
export function validateRequest(request){
  const binary=request.format==='njbc';
  if(request.format!==undefined&&!['js','njbc'].includes(request.format))throw new Error('Invalid format');
  if(binary?typeof request.bytecode!=='string'||!/^(?:[a-f\d]{2})+$/i.test(request.bytecode)||'code' in request:typeof request.code!=='string'||'bytecode' in request)throw new Error('Invalid code');
  bindingFor(request.namespace,binary?Buffer.from(request.bytecode,'hex'):Buffer.from(request.code),binary?'njbc':'js');
  if(!request.invoke||!['getPublicKey','signHash'].includes(request.invoke.name))throw new Error('Invalid export');
  const p=request.invoke.params;
  if(!p||Object.getPrototypeOf(p)!==Object.prototype||!Number.isInteger(p.keyIndex)||p.keyIndex<0||p.keyIndex>2147483647)throw new Error('Invalid key index');
  const signing=request.invoke.name==='signHash';
  if(signing&&(typeof p.hash!=='string'||!/^[a-f\d]{64}$/i.test(p.hash)))throw new Error('Invalid signing hash');
  if(Object.keys(p).some(k=>!['keyIndex',...(signing?['hash']:[])].includes(k)))throw new Error('Unexpected parameters');
  const result={namespace:request.namespace,...(binary?{format:'njbc',bytecode:request.bytecode}:{code:request.code}),invoke:{name:request.invoke.name,params:{keyIndex:p.keyIndex,...(signing?{hash:p.hash.toLowerCase()}: {})}}};
  if(Buffer.byteLength(JSON.stringify({command:'vmRun',...result,m:2147483647}))+1>32768)throw new Error('Request exceeds transport limit');
  return result;
}
