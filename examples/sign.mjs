import {parseArgs} from 'node:util';
import {appletRequest,parseVM,offlineTransfer,verifyOfflineTransfer} from '../lib/applet.mjs';
import {makeFixture} from '../tests/fixture.mjs';
const {values}=parseArgs({options:{format:{type:'string',default:'js'},network:{type:'string',default:'testnet'},'key-index':{type:'string',default:'0'}}});
const format=values.format,network=values.network,index=Number(values['key-index']);
const fixture=makeFixture();
// Replace fixture.invoke with your device's vmRun transport. Keep code and invoke separate.
const first=parseVM(fixture.invoke(appletRequest(index,'',network,format)),network,format);
const plan=offlineTransfer(first.publicKey,network);
const signature=parseVM(fixture.invoke(appletRequest(index,plan.hash,network,format)),network,format);
console.log(JSON.stringify({mode:'public-fixture',format,network,publicKey:signature.publicKey,signatureDER:signature.signatureDER,...verifyOfflineTransfer(plan,signature)},null,2));
