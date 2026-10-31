let state = {assets: [], discoveries: []}, engineState = {tasks: []}, scheduleEnabled = false;
const segmentRequests = new Set();
let selectedReport=null, reportData=null, reportRequest=0;
let assetPage=1;
let editingSchedule=null;
const el = id => document.getElementById(id);
const date = value => value ? new Date(value).toLocaleString() : '—';
const text = (id, value) => { if (el(id).textContent !== String(value)) el(id).textContent = value; };
function notice(message, error = false) { text('notice', message); el('notice').className = error ? 'notice error' : 'notice'; }
async function request(url, body) {
  const response = await fetch(url, body === undefined ? {} : {method: 'POST', headers: {'Content-Type':'application/json','X-Sentinel-Request':'1'}, body: JSON.stringify(body)});
  if (response.status === 401) throw new Error('Please sign in again with your current password.');
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || data.message || 'Request failed');
  return data;
}
function table(id, records, columns, empty) {
  const target = el(id); target.replaceChildren();
  if (!records.length) { const row = target.insertRow(); const cell = row.insertCell(); cell.colSpan = columns.length; cell.textContent = empty; cell.className = 'empty'; return; }
  for (const record of records) { const row = target.insertRow(); for (const column of columns) row.insertCell().textContent = column(record); }
}
function assets() {
  const query = el('asset-search').value.toLowerCase();
  const segment=el('asset-segment').value||'All';
  const filtered=state.assets.filter(a=>(segment==='All'||a.segment===segment)&&`${a.address} ${a.segment} ${a.hostname||''}`.toLowerCase().includes(query));
  const pages=Math.max(1,Math.ceil(filtered.length/25));assetPage=Math.min(assetPage,pages);
  table('asset-rows',filtered.slice((assetPage-1)*25,assetPage*25),[a=>a.address,a=>a.segment,a=>date(a.first_seen),a=>date(a.last_seen)],'No devices match these filters.');
  text('inventory-count',`${state.assets.length} devices · expand to browse`);
  text('asset-page',`Page ${assetPage} of ${pages} · ${filtered.length} devices`);
  el('asset-prev').disabled=assetPage<=1;el('asset-next').disabled=assetPage>=pages;
}
function renderSegments() {
  el('segments').replaceChildren();
  for (const [name,cidr] of Object.entries(state.segments || {})) {
    const card=document.createElement('article');
    const title=document.createElement('h3'); title.textContent=name;
    const subnet=document.createElement('p'); subnet.textContent=cidr;
    const count=document.createElement('strong'); count.textContent=`${state.assets.filter(a=>a.segment===name).length} assets observed`;
    const button=document.createElement('button');
    button.textContent=segmentRequests.has(cidr)?'Starting…':`Scan ${name}`;
    button.disabled=segmentRequests.has(cidr)||!engineState.profiles_ready;
    button.setAttribute('aria-label',`Start vulnerability scan for ${name}`);
    button.title=engineState.profiles_ready?'Start a Full and fast assessment for this segment':'Waiting for assessment profiles';
    button.addEventListener('click',async()=>{
      if(segmentRequests.has(cidr))return;
      segmentRequests.add(cidr);renderSegments();
      try {
        await request('/api/assessment',{scope:cidr,profile:'Full and fast',weekly:false});
        notice(`${name} vulnerability scan submitted. Follow progress in Live activity.`);
        await health();el('live-activity').scrollIntoView({behavior:'smooth',block:'start'});
      } catch(error) { notice(error.message,true); }
      finally { segmentRequests.delete(cidr);renderSegments(); }
    });
    card.append(title,subnet,count,button);el('segments').append(card);
  }
}
function severityBadge(category, score) {
  const badge=document.createElement('span');badge.className='severity '+category.toLowerCase();
  badge.textContent=category+(score===undefined?'':` · ${score.toFixed(1)}`);return badge;
}
function renderReports() {
  const body=el('report-rows');body.replaceChildren();
  if(!state.reports.length){table('report-rows',[],[()=>'',()=>'',()=>'',()=>''],'No completed assessment reports yet.');return;}
  for(const report of state.reports){
    const row=body.insertRow();row.insertCell().textContent=`${(report.segments||[]).join(' + ')||'Assessment'} · ${report.scope||'Scope unavailable'}`;row.insertCell().textContent=date(report.scan_end);row.insertCell().textContent=report.finding_count;
    const button=document.createElement('button');button.className='secondary';button.textContent='View report';
    button.addEventListener('click',async()=>{selectedReport={id:report.id,severity:'All',query:'',page:1};el('report-search').value='';try{await loadReport();el('report-detail').scrollIntoView({behavior:'smooth',block:'start'});}catch(error){notice(error.message,true);}});
    row.insertCell().append(button);
  }
}
function reportParameters() {return new URLSearchParams({report_id:selectedReport.id,severity:selectedReport.severity,q:selectedReport.query}).toString();}
async function loadReport() {
  const sequence=++reportRequest;
  const data=await request('/api/report?'+reportParameters());
  if(sequence!==reportRequest)return;
  reportData=data;el('report-detail').hidden=false;renderReport();
}
function renderReport() {
  if(!selectedReport||!reportData)return;
  text('report-title',`${(reportData.report.segments||[]).join(' + ')||'Assessment'} · ${reportData.report.scope}`);
  text('report-meta',`${reportData.report.task} · Completed ${date(reportData.report.scan_end)}`);
  el('severity-filters').replaceChildren();
  const categories=['All','Critical','High','Medium','Low','Informational','Unrated'];
  for(const category of categories){
    const button=document.createElement('button');button.className='severity-filter '+category.toLowerCase();
    button.textContent=`${category} · ${category==='All'?reportData.total:reportData.severity_counts[category]}`;
    button.setAttribute('aria-pressed',String(selectedReport.severity===category));
    button.addEventListener('click',async()=>{selectedReport.severity=category;selectedReport.page=1;try{await loadReport();}catch(error){notice(error.message,true);}});
    el('severity-filters').append(button);
  }
  el('report-csv').href='/reports/findings.csv?'+reportParameters();
  el('report-print').href='/reports/summary?'+reportParameters();
  text('report-result-count',`${reportData.filtered_count} matching findings from ${reportData.total} findings in this assessment. Open a finding to view evidence and remediation.`);
  const target=el('report-findings');target.replaceChildren();
  const pages=Math.max(1,Math.ceil(reportData.findings.length/50));selectedReport.page=Math.min(pages,selectedReport.page);
  const visible=reportData.findings.slice((selectedReport.page-1)*50,selectedReport.page*50);
  if(!visible.length){const empty=document.createElement('p');empty.className='muted';empty.textContent='No findings match these filters.';target.append(empty);}
  for(const finding of visible){
    const detail=document.createElement('details');detail.className='finding-detail';
    const summary=document.createElement('summary');summary.append(severityBadge(finding.severity_category,finding.severity));
    const name=document.createElement('strong');name.textContent=finding.name;summary.append(name);
    const asset=document.createElement('span');asset.className='muted small';asset.textContent=`${finding.host} · ${finding.segment} · ${finding.port}`;summary.append(asset);
    const cves=document.createElement('span');cves.className='muted small';cves.textContent=finding.cves.length?finding.cves.join(', '):'No CVE listed';summary.append(cves);detail.append(summary);
    const body=document.createElement('div');body.className='finding-body';
    if(finding.cves.length){const references=document.createElement('p');references.textContent='CVE references: ';for(const cve of finding.cves){const link=document.createElement('a');link.textContent=cve+' ';link.href='https://nvd.nist.gov/vuln/detail/'+encodeURIComponent(cve);link.target='_blank';link.rel='noopener';references.append(link);}body.append(references);}
    for(const [label,value] of [['Evidence',finding.evidence],['Remediation',finding.solution||'No remediation guidance supplied by scanner']]){const title=document.createElement('h4');title.textContent=label;const content=document.createElement('pre');content.textContent=value;body.append(title,content);}
    detail.append(body);target.append(detail);
  }
  text('report-page',`Page ${selectedReport.page} of ${pages}`);el('report-prev').disabled=selectedReport.page<=1;el('report-next').disabled=selectedReport.page>=pages;
}
const activeStates = new Set(['running','paused','stopping','Running','Requested','Queued','Resume Requested','Pausing','Stopping','Paused','Stop Requested','Stop Waiting']);
function scheduleInput(value) {
  const parts=new Intl.DateTimeFormat('en-CA',{timeZone:'America/New_York',year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'}).formatToParts(new Date(value));
  const p=Object.fromEntries(parts.map(part=>[part.type,part.value]));return `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}`;
}
function openSchedule(record=null) {
  editingSchedule=record?.task_id||null;
  el('scan-schedule-form').hidden=false;text('schedule-form-title',record?'Edit scan schedule':'Create scan schedule');
  el('schedule-name').value=record?.name||'';
  const scope=record?.scope||'192.168.10.0/24';
  const known=Object.values(state.segments||{}).includes(scope);
  el('schedule-target').value=known?scope:'custom';el('schedule-custom').value=known?'':scope;
  el('schedule-custom-label').hidden=known;el('schedule-custom').required=!known;
  el('schedule-target').disabled=Boolean(record);el('schedule-custom').disabled=Boolean(record);
  el('schedule-start').value=record?.next_run?scheduleInput(record.next_run):record?.start_local||scheduleInput(Date.now()+3600000);
  el('schedule-recurrence').value=['once','daily','weekly'].includes(record?.recurrence)?record.recurrence:'weekly';
  el('schedule-profile').value=record?.profile||'Full and fast';el('schedule-profile').disabled=Boolean(record);
  text('schedule-message','');el('scan-schedule-form').scrollIntoView({behavior:'smooth',block:'start'});
}
function renderSchedules() {
  const target=el('scan-schedule-list');target.replaceChildren();
  const schedules=engineState.schedules||[];
  if(!schedules.length){const p=document.createElement('p');p.className='muted';p.textContent='No scheduled assessments are available yet.';target.append(p);return;}
  for(const schedule of schedules){
    const card=document.createElement('article');card.className='schedule-card';
    const name=document.createElement('h3');name.textContent=schedule.name;
    const scope=document.createElement('p');scope.textContent=`${schedule.segments.join(' + ')||'Custom target'} · ${schedule.scope}`;
    const timing=document.createElement('p');
    const recurrence={once:'One time',daily:'Daily',weekly:'Weekly',advanced:'Advanced recurrence',unknown:'Timing unavailable'}[schedule.recurrence]||schedule.recurrence;
    let when='';
    if(schedule.start_local){when=new Date(schedule.start_local+'Z').toLocaleString('en-US',{timeZone:'UTC',weekday:schedule.recurrence==='weekly'?'long':undefined,hour:'numeric',minute:'2-digit'});}
    timing.textContent=`${recurrence}${when?' · '+when:''} Eastern`;
    const next=document.createElement('p');next.className='next-run';
    next.textContent=!schedule.enabled?'Disabled':schedule.next_run?'Next planned run: '+new Date(schedule.next_run).toLocaleString('en-US',{timeZone:schedule.timezone,dateStyle:'medium',timeStyle:'short'}):'No future run is scheduled';
    const actions=document.createElement('div');actions.className='actions';
    const edit=document.createElement('button');edit.className='secondary';edit.textContent='Edit time';edit.addEventListener('click',()=>openSchedule(schedule));actions.append(edit);
    actions.append(actionButton(schedule.enabled?'Disable':'Enable',()=>request('/api/scan-schedules/enabled',{task_id:schedule.task_id,enabled:!schedule.enabled})));
    card.append(name,scope,timing,next,actions);target.append(card);
  }
}
function displayStatus(status) {
  return {done:'Completed',Done:'Completed',running:'Running',paused:'Paused',stopped:'Stopped',Stopped:'Stopped',failed:'Failed',interrupted:'Interrupted',Interrupted:'Interrupted',stopping:'Stopping',Requested:'Queued','Internal Error':'Failed'}[status] || status;
}
function actionButton(label, callback) {
  const button = document.createElement('button'); button.className = 'secondary'; button.textContent = label;
  button.addEventListener('click', async () => { button.disabled = true; try { await callback(); await Promise.all([refresh(),health()]); } catch (e) { notice(e.message,true); button.disabled = false; } });
  return button;
}
function jobCard(job, type) {
  const discovery = type === 'discovery', status = job.status;
  const raw = job.progress;
  const hasProgress = !discovery && raw !== null && raw !== undefined && String(raw).trim() !== '' && Number.isFinite(Number(raw)) && Number(raw) >= 0;
  const percent = status==='Done'?100:hasProgress?Math.min(100,Math.round(Number(raw))):null;
  const card = document.createElement('article'); card.className = 'scan-card';
  const header = document.createElement('div'); header.className = 'section-head';
  const name = document.createElement('strong'); name.textContent = discovery ? `Device discovery · ${job.scope}` : job.name;
  const chip = document.createElement('span'); chip.className = 'state-chip'; chip.textContent = displayStatus(status)+(percent===null?'':` · ${percent}%`);
  if (status === 'Paused' || status === 'paused') chip.classList.add('paused');
  header.append(name,chip); card.append(header);
  if (activeStates.has(status) || status==='Done') {
    const label=document.createElement('p');label.className='progress-label';
    label.textContent=percent===null?'Progress percentage unavailable':`${percent}% complete · ${100-percent}% remaining`;
    card.append(label);
    const bar = document.createElement('progress'); bar.max = 100;
    bar.setAttribute('aria-label', discovery ? 'Discovery progress' : 'Assessment progress');
    if (percent!==null) {bar.value=percent;bar.setAttribute('aria-valuetext',label.textContent);}
    if (['paused','Paused','stopping','Stopping','Pausing'].includes(status)) { bar.className = 'paused'; if (discovery) bar.value = 0; }
    card.append(bar);
  }
  const actions = document.createElement('div'); actions.className = 'actions';
  const control = action => request(discovery ? '/api/discovery/control' : '/api/assessment/control', discovery ? {id:job.id,action} : {task_id:job.id,action});
  if (['running','Running','Requested','Queued','Resume Requested'].includes(status)) actions.append(actionButton('Pause',()=>control('pause')),actionButton('Stop',()=>control('stop')));
  if (status === 'paused' || status === 'Paused') actions.append(actionButton('Resume',()=>control('resume')),actionButton('Stop',()=>control('stop')));
  if (!discovery && status !== 'Paused' && job.can_resume) actions.append(actionButton('Resume',()=>control('resume')));
  if (!discovery && ['New','Done','Stopped','Interrupted'].includes(status)) actions.append(actionButton(status === 'New' ? 'Run now' : 'Run again',()=>control('start')));
  if (!discovery && job.schedule_id && job.schedule_id !== '0') {const link=document.createElement('a');link.href='#scan-schedules';link.className='button secondary';link.textContent='View schedule';actions.append(link);}
  if (actions.children.length) card.append(actions);
  return card;
}
function renderActivity() {
  const currentDiscovery = state.discoveries.filter(d=>activeStates.has(d.status));
  const currentEngine = (engineState.tasks || []).filter(t=>activeStates.has(t.status));
  const jobs = [...currentDiscovery,...currentEngine];
  const running = jobs.some(j=>!['paused','Paused'].includes(j.status));
  el('live-activity').classList.toggle('is-running',running);
  el('live-activity').classList.toggle('is-paused',jobs.length>0&&!running);
  text('live-title',running ? 'Scan in progress' : jobs.length ? 'Scanning paused' : 'No scan is running');
  text('live-description',running ? 'Activity updates automatically. Pause or stop a scan below.' : jobs.length ? 'Resume a paused scan when you are ready.' : 'Start discovery or an assessment to see live progress here.');
  el('live-jobs').replaceChildren();
  for (const job of currentDiscovery) el('live-jobs').append(jobCard(job,'discovery'));
  for (const job of currentEngine) el('live-jobs').append(jobCard(job,'assessment'));
  el('engine-tasks').replaceChildren();
  for (const task of engineState.tasks || []) el('engine-tasks').append(jobCard(task,'assessment'));
  if (!(engineState.tasks || []).length) { const p=document.createElement('p');p.className='muted small';p.textContent='No vulnerability assessments have been created yet.';el('engine-tasks').append(p); }
}
async function refresh() {
  state = await request('/api/state');
  const phases={not_started:'Initial validation has not started.',waiting_for_profiles:'Initial setup: loading vulnerability data and assessment profiles.',validation_created:'Initial setup: preparing the test assessment.',validation_running:'Initial setup: test assessment in progress.',validation_paused:'Initial setup: test assessment paused or interrupted. Resume it below to continue.',creating_weekly_schedules:'Initial setup: configuring weekly assessments.',complete:'Initial assessment and report exports verified. Weekly assessments configured.'};
  text('setup-state',phases[state.setup?.phase] || 'Setup status unavailable.');
  if(state.setup?.last_error) text('setup-state',el('setup-state').textContent+' Setup is retrying or needs administrator attention.');
  text('asset-count',state.assets.length); text('high-count',state.counts.high); text('finding-count',state.counts.findings); text('report-count',state.reports.length);
  renderSegments();
  assets();
  renderReports();
  table('activity-rows',state.discoveries,[d=>d.scope,d=>displayStatus(d.status)+(d.error?' · '+d.error:''),d=>date(d.started),d=>date(d.finished)],'No discovery jobs yet.');
  scheduleEnabled=state.settings.some(s=>s.key==='discovery_enabled'&&s.value==='true');
  text('schedule',scheduleEnabled?'Disable scheduled discovery':'Enable scheduled discovery');
  renderActivity();
}
async function health() {
  try {
    engineState=await request('/api/engine');
    text('engine',engineState.profiles_ready?'Engine connected · profiles available':'Engine loading assessment profiles');
    el('engine').className=engineState.profiles_ready?'badge good':'badge';
    el('engine-feeds').replaceChildren();
    for(const feed of engineState.feeds){const p=document.createElement('p');p.textContent=`${feed.name||feed.type}: feed version ${feed.version||'not yet loaded'}`;el('engine-feeds').append(p);}
  } catch { text('engine','Engine unavailable · retrying');el('engine').className='badge'; }
  renderSegments();
  renderSchedules();
  renderActivity();
}
async function loadSettings() {
  const settings=await request('/api/settings');
  el('settings-enabled').checked=settings.discovery_enabled;
  for(const key of ['discovery_interval_hours','discovery_rate','max_hosts','max_checks']) el('settings-'+key).value=settings[key];
}
async function openSettings(event) {
  if(event)event.preventDefault();el('settings').hidden=false;
  try{await loadSettings();el('settings').scrollIntoView({behavior:'smooth',block:'start'});}catch(e){notice(e.message,true);}
}
el('settings-open').addEventListener('click',openSettings);
el('settings-link').addEventListener('click',openSettings);
el('settings-close').addEventListener('click',()=>{el('settings').hidden=true;el('password-form').reset();});
el('settings-form').addEventListener('submit',async event=>{
  event.preventDefault();const button=event.target.querySelector('button');button.disabled=true;
  try{const body={discovery_enabled:el('settings-enabled').checked};for(const key of ['discovery_interval_hours','discovery_rate','max_hosts','max_checks'])body[key]=Number(el('settings-'+key).value);await request('/api/settings',body);notice('Settings saved. Scan limits apply to newly created assessments.');await refresh();}catch(e){notice(e.message,true);}finally{button.disabled=false;}
});
el('password-form').addEventListener('submit',async event=>{
  event.preventDefault();const current=el('current-password').value,replacement=el('new-password').value;
  if(replacement!==el('confirm-password').value){text('password-message','The new passwords do not match.');return;}
  const button=event.target.querySelector('button');button.disabled=true;
  try{await request('/api/password',{current_password:current,new_password:replacement});event.target.reset();text('password-message','Password changed. Refresh the page and sign in as admin using your new password.');clearInterval(stateTimer);clearInterval(engineTimer);}catch(e){text('password-message',e.message);}finally{button.disabled=false;}
});
el('asset-search').addEventListener('input',()=>{assetPage=1;assets();});
el('asset-segment').addEventListener('change',()=>{assetPage=1;assets();});
el('assets-link').addEventListener('click',()=>{el('assets').open=true;});
el('schedule-create').addEventListener('click',()=>openSchedule());
el('schedule-cancel').addEventListener('click',()=>{el('scan-schedule-form').hidden=true;editingSchedule=null;});
el('schedule-target').addEventListener('change',()=>{const custom=el('schedule-target').value==='custom';el('schedule-custom-label').hidden=!custom;el('schedule-custom').required=custom;});
el('scan-schedule-form').addEventListener('submit',async event=>{
  event.preventDefault();el('schedule-save').disabled=true;
  const payload={name:el('schedule-name').value,scope:el('schedule-target').value==='custom'?el('schedule-custom').value:el('schedule-target').value,start:el('schedule-start').value,recurrence:el('schedule-recurrence').value,profile:el('schedule-profile').value};
  if(editingSchedule)payload.task_id=editingSchedule;
  try{await request('/api/scan-schedules',payload);el('scan-schedule-form').hidden=true;editingSchedule=null;notice('Scan schedule saved. It will run at the selected time.');await health();}catch(error){text('schedule-message',error.message);}finally{el('schedule-save').disabled=false;}
});
el('asset-prev').addEventListener('click',()=>{if(assetPage>1){assetPage--;assets();}});
el('asset-next').addEventListener('click',()=>{assetPage++;assets();});
el('report-close').addEventListener('click',()=>{selectedReport=null;reportData=null;reportRequest++;el('report-detail').hidden=true;});
el('report-filter-form').addEventListener('submit',async event=>{event.preventDefault();if(!selectedReport)return;selectedReport.query=el('report-search').value;selectedReport.page=1;try{await loadReport();}catch(error){notice(error.message,true);}});
el('report-prev').addEventListener('click',()=>{if(selectedReport&&selectedReport.page>1){selectedReport.page--;renderReport();}});
el('report-next').addEventListener('click',()=>{if(selectedReport){selectedReport.page++;renderReport();}});
el('refresh').addEventListener('click',()=>Promise.all([refresh(),health()]).catch(e=>notice(e.message,true)));
el('discovery-form').addEventListener('submit',async event=>{event.preventDefault();try{await request('/api/discovery',{scope:el('scope').value});notice('Discovery started. Watch its progress in Live activity.');await refresh();}catch(e){notice(e.message,true);}});
el('schedule').addEventListener('click',async()=>{try{await request('/api/schedule',{enabled:!scheduleEnabled});await refresh();notice(scheduleEnabled?'Scheduled discovery enabled.':'Scheduled discovery disabled.');}catch(e){notice(e.message,true);}});
el('sync').addEventListener('click',async()=>{try{await request('/api/sync',{});await refresh();notice('Completed engine reports imported.');}catch(e){notice(e.message,true);}});
el('assessment-form').addEventListener('submit',async event=>{event.preventDefault();const button=event.target.querySelector('button');button.disabled=true;try{await request('/api/assessment',{scope:el('assessment-scope').value,profile:el('profile').value,weekly:el('weekly').checked});notice('Assessment submitted. Watch its progress in Live activity.');await health();}catch(e){notice(e.message,true);}finally{button.disabled=false;}});
Promise.all([refresh(),health()]).catch(e=>notice(e.message,true));
const stateTimer=setInterval(()=>refresh().catch(()=>{}),5000);
const engineTimer=setInterval(health,10000);
