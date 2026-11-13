import { parse, tokenizer } from 'acorn';
import { analyze } from 'eslint-scope';
import { generate } from 'astring';
import { readFileSync } from 'node:fs';

const MAX = 0xffffff;
const magic = Buffer.from([78, 74, 66, 67, 2]);
const commands = [...readFileSync(new URL('./commands.def', import.meta.url),'utf8').matchAll(/^NVM_COMMAND\((".*")\)$/gm)].map(m=>JSON.parse(m[1]));
const commandIds = new Map(commands.map((text,id)=>[text,id]));
const allowed = new Set(['Program','VariableDeclaration','VariableDeclarator','Identifier','Literal','ExpressionStatement','BlockStatement','EmptyStatement','IfStatement','ForStatement','BreakStatement','ContinueStatement','ReturnStatement','FunctionExpression','CallExpression','MemberExpression','ObjectExpression','Property','AssignmentExpression','BinaryExpression','LogicalExpression','UnaryExpression','UpdateExpression','ConditionalExpression']);
const operators = new Set(['=','+=','-=','*=','/=','%=','<<=','>>=','&=','^=','|=','+','-','*','/','%','<<','>>','&','^','|','===','!==','<','<=','>','>=','&&','||','!','~','typeof','++','--']);
function walk(node, visit) {
  if (!node || typeof node !== 'object') return;
  if (node.type) visit(node);
  for (const value of Object.values(node)) {
    if (Array.isArray(value)) value.forEach(x => walk(x, visit));
    else if (value && typeof value === 'object') walk(value, visit);
  }
}
function syntax(source) {
  const ast = parse(source, {ecmaVersion: 2022, ranges: true});
  walk(ast, n => {
    if (!allowed.has(n.type) || n.computed || n.async || n.generator ||
        (n.type === 'VariableDeclaration' && n.kind !== 'let') ||
        (n.type === 'Literal' && (n.regex || n.bigint)) ||
        (n.type === 'Property' && (n.method || n.kind !== 'init')) ||
        (n.type === 'FunctionExpression' && n.id) || n.label ||
        (n.operator && !operators.has(n.operator)))
      throw new Error(`Unsupported NucleoVM syntax: ${n.type}`);
  });
  return ast;
}
function varint(n) {
  const bytes=[];
  do { const b=n%128; n=Math.floor(n/128); bytes.push(b|(n?128:0)); } while(n);
  return Buffer.from(bytes);
}
export function compile(source, {publicFunctions=[]}={}) {
  if (Buffer.byteLength(source)>MAX) throw new Error('Source too large');
  const ast=syntax(source);
  const publics=new Set(publicFunctions);
  for (const name of publics) {
    if (!ast.body.some(n=>n.type==='VariableDeclaration' && n.declarations.some(d=>d.id.name===name && d.init?.type==='FunctionExpression')))
      throw new Error(`Public function must be a top-level let function: ${name}`);
  }
  // Keep property keys intact when a shorthand binding is renamed.
  walk(ast,n=>{if(n.type==='Property' && n.shorthand){n.key={...n.key};n.shorthand=false;}});
  const scopes=analyze(ast,{ecmaVersion:2022,sourceType:'script'});
  const renamed=scopes.scopes.flatMap(scope=>scope.variables.filter(variable=>variable.defs.length && !(scope.type==='global' && publics.has(variable.name))));
  const targets=new Set(renamed.flatMap(v=>[...v.identifiers,...v.references.map(r=>r.identifier)]));
  const occupied=new Set();
  walk(ast,n=>{if(n.type==='Identifier' && !targets.has(n))occupied.add(n.name);});
  let next=0;
  for(const variable of renamed) {
    let name; do{name=`v${next++}`;}while(occupied.has(name)); occupied.add(name);
    for(const id of variable.identifiers)id.name=name;
    for(const ref of variable.references)ref.identifier.name=name;
  }
  const normalized=generate(ast);
  const tables=[commands,[],[],[]], maps=[commandIds,...[0,1,2].map(()=>new Map())], stream=[];
  for(const token of tokenizer(normalized,{ecmaVersion:2022})) {
    const raw=normalized.slice(token.start,token.end);
    const kind=token.type.label==='string'?2:token.type.label==='num'?3:commandIds.has(raw)?0:token.type.label==='name'?1:0;
    let id=maps[kind].get(raw);
    if(id===undefined){if(kind===0)throw new Error(`Unknown command: ${raw}`);id=tables[kind].length;tables[kind].push(raw);maps[kind].set(raw,id);}
    stream.push({kind,id});
  }
  if(tables[0].length>128)throw new Error('Command dictionary too large');
  const parts=[magic];
  for(const table of tables.slice(1)){parts.push(varint(table.length));for(const entry of table){const data=Buffer.from(entry);parts.push(varint(data.length),data);}}
  parts.push(varint(publicFunctions.length));
  for(const name of publicFunctions)parts.push(varint(maps[1].get(name)));
  parts.push(varint(stream.length));
  for(const {kind,id} of stream)parts.push(kind===0?Buffer.from([id]):Buffer.concat([Buffer.from([127+kind]),varint(id)]));
  const result=Buffer.concat(parts);
  if(result.length>MAX)throw new Error('Bytecode too large');
  return result;
}
export function decompile(input) {
  const data=Buffer.from(input);let at=5;
  if(data.length>MAX || !data.subarray(0,5).equals(magic))throw new Error('Invalid NJBC header');
  const read=()=>{let n=0;for(let shift=0;shift<28;shift+=7){if(at>=data.length)throw new Error('Truncated bytecode');const b=data[at++];n+=(b&127)*2**shift;if(n>MAX)throw new Error('Format limit');if(!(b&128))return n;}throw new Error('Invalid varint');};
  const utf8=new TextDecoder('utf-8',{fatal:true});
  const tables=[commands];
  for(let k=0;k<3;k++){const table=[];const count=read();if(count>data.length-at)throw new Error('Invalid table');for(let i=0;i<count;i++){const len=read();if(len>data.length-at)throw new Error('Truncated table');table.push(utf8.decode(data.subarray(at,at+len)));at+=len;}tables.push(table);}
  if(tables[0].length>128)throw new Error('Invalid commands');
  const publicFunctions=[];const publicCount=read();
  for(let i=0;i<publicCount;i++){const id=read();if(id>=tables[1].length)throw new Error('Invalid public symbol');publicFunctions.push(tables[1][id]);}
  const count=read(), tokens=[];
  if(count>data.length-at)throw new Error('Invalid token count');
  for(let i=0;i<count;i++){if(at>=data.length)throw new Error('Truncated tokens');const op=data[at++];const kind=op<128?0:op-127;if(kind>3)throw new Error('Invalid opcode');const id=kind===0?op:read();if(id>=tables[kind].length)throw new Error('Invalid dictionary reference');tokens.push(tables[kind][id]);}
  if(at!==data.length)throw new Error('Trailing bytes');
  const source=tokens.join(' ');
  if(Buffer.byteLength(source)>MAX)throw new Error('Expanded source too large');
  syntax(source);
  return {source:source+'\n', publicFunctions};
}
