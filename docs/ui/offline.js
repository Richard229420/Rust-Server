(async function () {
  "use strict";
  const operations = document.getElementById('operations');
  const fields = document.getElementById('parameter-fields');
  const bodyWrap = document.getElementById('body-field');
  const body = document.getElementById('request-body');
  const execute = document.getElementById('execute');
  const result = document.getElementById('result');
  const status = document.getElementById('status');
  const title = document.getElementById('operation-title');
  const description = document.getElementById('description');
  const token = document.querySelector('meta[name="lab-token"]').content;
  let selected;
  const sample = {
    POST: {name:'Ana Silva',email:'ana@example.com'},
    PUT: {name:'Ana Atualizada',email:'ana.atualizada@example.com'},
    PATCH: {name:'Ana Atualizada'}
  };
  try {
    const response = await fetch('/openapi.json', {cache:'no-store'});
    if (!response.ok) throw new Error('OpenAPI: HTTP ' + response.status);
    const spec = await response.json();
    operations.replaceChildren();
    for (const [path, methods] of Object.entries(spec.paths)) {
      for (const [method, op] of Object.entries(methods)) {
        if (!['get','post','put','patch','delete'].includes(method)) continue;
        const entry = {path, method:method.toUpperCase(), op};
        const btn = document.createElement('button');
        btn.className='operation';
        btn.textContent = `${entry.method}  ${entry.path}`;
        btn.addEventListener('click', () => select(entry));
        operations.appendChild(btn);
        if (!selected) select(entry);
      }
    }
    function select(entry) {
      selected=entry;
      title.textContent=`${entry.method} ${entry.path}`;
      description.textContent=entry.op.description || entry.op.summary || '';
      fields.replaceChildren();
      if (entry.path.includes('{id}')) addField('id', 'ID do usuário', '1');
      if (entry.method==='GET' && !entry.path.includes('{id}')) {
        addField('limit','Limite (1 a 100)','20'); addField('offset','Offset','0');
      }
      bodyWrap.hidden=!['POST','PUT','PATCH'].includes(entry.method);
      if (!bodyWrap.hidden) body.value=JSON.stringify(sample[entry.method],null,2);
      status.textContent='Nenhuma execução'; result.textContent='—'; execute.disabled=false;
    }
    function addField(name,labelText,defaultValue) {
      const label=document.createElement('label'); label.textContent=labelText; label.htmlFor='field-'+name;
      const input=document.createElement('input'); input.id='field-'+name; input.value=defaultValue;
      label.appendChild(input); fields.appendChild(label);
    }
  } catch (error) { operations.textContent=String(error); }
  execute.addEventListener('click',async () => {
    if (!selected) return;
    execute.disabled=true; status.textContent='Executando…'; result.textContent='';
    try {
      let path=selected.path;
      if (path.includes('{id}')) path=path.replace('{id}',encodeURIComponent(document.getElementById('field-id').value));
      else if (selected.method==='GET') {
        const qs=new URLSearchParams({limit:document.getElementById('field-limit').value,offset:document.getElementById('field-offset').value});
        path+='?'+qs;
      }
      const opts={method:selected.method,headers:{'X-Lab-Token':token,'Accept':'application/json'}};
      if (!bodyWrap.hidden) {opts.headers['Content-Type']='application/json';opts.body=body.value;}
      const response=await fetch(path,opts);
      status.textContent=`HTTP ${response.status} ${response.statusText}`;
      const raw=await response.text();
      try { result.textContent=JSON.stringify(JSON.parse(raw),null,2); }
      catch { result.textContent=raw || '(Sem corpo: esperado para HTTP 204)'; }
    } catch (error) {status.textContent='Falha de conexão'; result.textContent=String(error);}
    execute.disabled=false;
  });
}());
