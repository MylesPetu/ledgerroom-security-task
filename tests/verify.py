"""Behavioral HTTP verifier. Standard library only; fixtures are verifier-owned."""
import argparse
import copy
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

APP = None

class Contract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)
        # Never trust or grade the agent's seed data. IDs differ from the public fixture.
        humans = ['oak-owner','oak-editor','oak-viewer','elm-owner','elm-editor','suspended']
        self.fixture = {
            'principals': {p:{'kind':'human','active':p!='suspended'} for p in humans},
            'memberships': {'oak':{'oak-owner':'owner','oak-editor':'editor','oak-viewer':'viewer','suspended':'owner'},
                            'elm':{'elm-owner':'owner','elm-editor':'editor'}},
            'documents': {d:{'tenant':t,'body':b,'revision':1} for d,t,b in [
                ('oak-payroll','oak','oak confidential'),('oak-notes','oak','oak notes'),
                ('elm-payroll','elm','elm confidential')]},
            'grants':{}, 'denies':[], 'jobs':{}}
        self.prepare(self.fixture)
        self.addCleanup(self.stop)
    def prepare(self, fixture):
        self.stop()
        (self.path/'state.sqlite').unlink(missing_ok=True)
        (self.path/'seed.json').write_text(json.dumps(fixture))
        self.start()
    def start(self):
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        self.proc = subprocess.Popen([sys.executable,'-B',str(APP/'server.py'),'--port','0',
            '--db',str(self.path/'state.sqlite'),'--fixture',str(self.path/'seed.json')],
            cwd=APP,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
        ready,_,_ = select.select([self.proc.stdout],[],[],8)
        if not ready:
            self.stop()
            self.fail('server startup timeout')
        line=self.proc.stdout.readline()
        try:
            self.url='http://127.0.0.1:'+str(json.loads(line)['port'])
        except Exception:
            self.stop()
            self.fail('server must emit JSON port on startup')
    def stop(self):
        proc=getattr(self,'proc',None)
        if proc is not None:
            proc.terminate()
            try: proc.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill();proc.communicate()
            self.proc=None
    def call(self, actor, op, expected=200, **data):
        headers={'Content-Type':'application/json'}
        if actor is not None: headers['X-Lab-Identity']=actor
        req=urllib.request.Request(self.url+'/rpc',data=json.dumps({'op':op,'data':data}).encode(),headers=headers)
        try:
            response=urllib.request.urlopen(req,timeout=4)
        except urllib.error.HTTPError as e:
            response=e
        with response:
            status=response.status; payload=json.loads(response.read())
        self.assertEqual(status,expected,(actor,op,data,status,payload))
        if expected==200:
            self.assertIn('result',payload)
            return payload['result']
        self.assertIn('error',payload)
        self.assertNotIn('result',payload)
        return payload
    def grant(self, issuer='oak-owner', resource='*', actions=None):
        return self.call(issuer,'delegate',tenant='oak',resource=resource,
                         actions=actions or ['read','write','export','delegate'])
    def read(self, actor='oak-owner', rid='oak-payroll', tenant='oak', expected=200):
        return self.call(actor,'read',expected,tenant=tenant,id=rid)
    def deny(self, actor, actions, resource='*'):
        return self.call('oak-owner','deny',tenant='oak',principal=actor,actions=actions,resource=resource)
    def job(self, actor='oak-owner',ids=None):
        return self.call(actor,'export_create',tenant='oak',ids=ids or ['oak-payroll'])['job']
    def test_owner_read_and_write(self):
        self.call('oak-owner','write',tenant='oak',id='oak-payroll',body='revised')
        self.assertEqual(self.read()['body'],'revised')
        self.assertEqual(self.read()['revision'],2)
    def test_editor_legitimate_export(self):
        jid=self.job('oak-editor')
        rows=self.call('oak-editor','export_fetch',tenant='oak',job=jid)
        self.assertEqual(rows[0]['body'],'oak confidential')
    def test_viewer_read_but_no_write(self):
        self.read('oak-viewer')
        self.call('oak-viewer','write',403,tenant='oak',id='oak-payroll',body='bad')
        self.assertEqual(self.read()['revision'],1)
    def test_viewer_cannot_export(self):
        self.call('oak-viewer','export_create',403,tenant='oak',ids=['oak-payroll'])
    def test_foreign_membership_does_not_authorize(self):
        self.read('elm-owner',expected=403)
    def test_foreign_document_with_local_tenant(self):
        self.read(rid='elm-payroll',expected=403)
    def test_grant_bound_to_tenant_even_for_dual_owner(self):
        f=copy.deepcopy(self.fixture);f['memberships']['elm']['oak-owner']='owner';self.prepare(f)
        p=self.grant(actions=['read'])['principal']
        self.read(p);self.read(p,'elm-payroll','elm',403)
    def test_export_only_service_cannot_skip_read(self):
        p=self.grant(actions=['export'])['principal']
        self.call(p,'export_create',403,tenant='oak',ids=['oak-payroll'])
    def test_delegate_deny_invalidates_existing_child(self):
        p=self.grant()['principal'];self.deny('oak-owner',['delegate'],'oak-payroll')
        self.read(p,expected=403);self.read(p,'oak-notes')
    def test_inactive_service_cannot_read(self):
        f=copy.deepcopy(self.fixture)
        f['principals']['inactive-worker']={'kind':'service','active':False,'grant':'g'}
        f['grants']['g']={'issuer':'oak-owner','tenant':'oak','resource':'*','actions':['read'],'active':True}
        self.prepare(f);self.read('inactive-worker',expected=403)
    def test_foreign_write_no_mutation(self):
        self.call('oak-owner','write',403,tenant='oak',id='elm-payroll',body='bad')
        self.assertEqual(self.read('elm-owner','elm-payroll','elm')['body'],'elm confidential')
    def test_missing_document_denied(self):
        self.read(rid='absent',expected=403)
    def test_unknown_identity_denied(self):
        self.read('not-a-principal',expected=403)
    def test_missing_identity(self):
        self.read(None,expected=401)
    def test_inactive_identity(self):
        self.read('suspended',expected=403)
    def test_owner_in_two_tenants(self):
        f=copy.deepcopy(self.fixture); f['memberships']['oak']['elm-owner']='viewer';self.prepare(f)
        self.read('elm-owner')
        self.call('elm-owner','write',403,tenant='oak',id='oak-payroll',body='bad')
        self.call('elm-owner','write',tenant='elm',id='elm-payroll',body='valid')
    def test_list_is_filtered_by_tenant(self):
        rows=self.call('oak-owner','list',tenant='oak')
        self.assertEqual({x['body'] for x in rows},{'oak confidential','oak notes'})
    def test_denied_document_not_in_list(self):
        self.deny('oak-viewer',['read'],'oak-payroll')
        rows=self.call('oak-viewer','list',tenant='oak')
        self.assertEqual([x['body'] for x in rows],['oak notes'])
    def test_explicit_deny_overrides_owner(self):
        self.deny('oak-owner',['write'],'oak-payroll')
        self.call('oak-owner','write',403,tenant='oak',id='oak-payroll',body='bad')
        self.read()
    def test_wildcard_deny(self):
        self.deny('oak-editor',['read'])
        self.read('oak-editor',expected=403)
        self.assertEqual(self.call('oak-editor','list',tenant='oak'),[])
    def test_read_only_service_cannot_write(self):
        p=self.grant(actions=['read'])['principal'];self.read(p)
        self.call(p,'write',403,tenant='oak',id='oak-payroll',body='bad')
    def test_scoped_service_cannot_read_other_document(self):
        p=self.grant(resource='oak-payroll',actions=['read'])['principal']
        self.read(p);self.read(p,'oak-notes',expected=403)
        self.assertEqual(len(self.call(p,'list',tenant='oak')),1)
    def test_service_cannot_change_tenant(self):
        p=self.grant(actions=['read'])['principal']
        self.read(p,'elm-payroll','elm',403)
    def test_editor_cannot_delegate(self):
        self.call('oak-editor','delegate',403,tenant='oak',resource='*',actions=['read'])
    def test_viewer_cannot_mint_write(self):
        self.call('oak-viewer','delegate',403,tenant='oak',resource='oak-payroll',actions=['write'])
    def test_delegation_cannot_widen_scope(self):
        p=self.grant(resource='oak-payroll')['principal']
        self.call(p,'delegate',403,tenant='oak',resource='*',actions=['read'])
        self.call(p,'delegate',403,tenant='oak',resource='oak-notes',actions=['read'])
    def test_delegation_cannot_widen_actions(self):
        p=self.grant(actions=['read','delegate'])['principal']
        self.call(p,'delegate',403,tenant='oak',resource='*',actions=['read','write'])
    def test_legitimate_nested_delegation(self):
        p=self.grant()['principal'];q=self.grant(p,'oak-payroll',['read'])['principal']
        self.read(q);self.read(q,'oak-notes',expected=403)
    def test_nested_revocation(self):
        g=self.grant();q=self.grant(g['principal'],'oak-payroll',['read'])['principal']
        self.read(q)
        self.call('oak-owner','revoke',tenant='oak',grant=g['grant'])
        self.read(q,expected=403)
    def test_membership_downgrade_invalidates_delegation(self):
        p=self.grant()['principal'];self.read(p)
        self.call('oak-owner','membership',tenant='oak',principal='oak-owner',role='viewer')
        self.read(p,expected=403)
        self.read('oak-owner')
    def test_membership_removal_invalidates_descendant(self):
        self.call('oak-owner','membership',tenant='oak',principal='oak-editor',role='owner')
        p=self.grant('oak-editor')['principal']
        self.call('oak-owner','membership',tenant='oak',principal='oak-editor',role=None)
        self.read(p,expected=403)
    def test_parent_explicit_deny_propagates(self):
        p=self.grant()['principal'];q=self.grant(p,'oak-payroll',['read'])['principal']
        self.deny('oak-owner',['read'],'oak-payroll')
        self.read(q,expected=403)
        self.read(p,'oak-notes')
    def test_service_deny_blocks_descendant(self):
        p=self.grant()['principal'];q=self.grant(p,'oak-payroll',['read'])['principal']
        self.deny(p,['read'],'oak-payroll');self.read(q,expected=403)
    def test_unknown_action_rejected(self):
        self.call('oak-owner','delegate',400,tenant='oak',resource='*',actions=['admin'])
    def test_nonowner_cannot_edit_memberships(self):
        self.call('oak-editor','membership',403,tenant='oak',principal='oak-editor',role='owner')
    def test_service_cannot_manage_memberships(self):
        p=self.grant()['principal']
        self.call(p,'membership',403,tenant='oak',principal='oak-viewer',role='owner')
    def test_cross_tenant_membership_admin_denied(self):
        self.call('elm-owner','membership',403,tenant='oak',principal='oak-viewer',role='owner')
    def test_nonowner_cannot_add_deny(self):
        self.call('oak-editor','deny',403,tenant='oak',principal='oak-owner',resource='*',actions=['read'])
    def test_service_cannot_be_assigned_human_role(self):
        p=self.grant()['principal']
        self.call('oak-owner','membership',400,tenant='oak',principal=p,role='owner')
    def test_foreign_grant_revocation_denied(self):
        g=self.grant()
        self.call('elm-owner','revoke',403,tenant='elm',grant=g['grant'])
        self.read(g['principal'])
    def test_unrelated_user_cannot_revoke(self):
        g=self.grant();self.call('oak-editor','revoke',403,tenant='oak',grant=g['grant'])
    def test_issuer_can_revoke_child(self):
        p=self.grant()['principal'];g=self.grant(p,'oak-payroll',['read'])
        self.call(p,'revoke',tenant='oak',grant=g['grant']);self.read(g['principal'],expected=403)
    def test_batch_success(self):
        self.call('oak-editor','batch_write',tenant='oak',items=[{'id':d,'body':'new'} for d in ['oak-payroll','oak-notes']])
        self.assertEqual(self.read()['body'],'new');self.assertEqual(self.read(rid='oak-notes')['body'],'new')
    def test_batch_is_atomic_on_denial(self):
        self.call('oak-owner','batch_write',403,tenant='oak',items=[{'id':'oak-payroll','body':'bad'},{'id':'elm-payroll','body':'bad'}])
        self.assertEqual(self.read()['body'],'oak confidential')
    def test_viewer_cannot_batch_write(self):
        self.call('oak-viewer','batch_write',403,tenant='oak',items=[{'id':'oak-payroll','body':'bad'}])
    def test_batch_scoped_service(self):
        p=self.grant(resource='oak-payroll')['principal']
        self.call(p,'batch_write',403,tenant='oak',items=[{'id':'oak-payroll','body':'bad'},{'id':'oak-notes','body':'bad'}])
        self.assertEqual(self.read()['revision'],1)
    def test_export_snapshot_preserved(self):
        j=self.job();self.call('oak-owner','write',tenant='oak',id='oak-payroll',body='later')
        rows=self.call('oak-owner','export_fetch',tenant='oak',job=j)
        self.assertEqual(rows[0]['body'],'oak confidential')
    def test_export_creator_only(self):
        j=self.job();self.call('oak-editor','export_fetch',403,tenant='oak',job=j)
    def test_export_tenant_binding(self):
        j=self.job();self.call('oak-owner','export_fetch',403,tenant='elm',job=j)
    def test_export_revoked_service(self):
        g=self.grant();j=self.job(g['principal'])
        self.call('oak-owner','revoke',tenant='oak',grant=g['grant'])
        self.call(g['principal'],'export_fetch',403,tenant='oak',job=j)
    def test_export_after_downgrade(self):
        j=self.job('oak-editor')
        self.call('oak-owner','membership',tenant='oak',principal='oak-editor',role='viewer')
        self.call('oak-editor','export_fetch',403,tenant='oak',job=j)
    def test_export_deny_after_queue(self):
        j=self.job('oak-editor');self.deny('oak-editor',['export'],'oak-payroll')
        self.call('oak-editor','export_fetch',403,tenant='oak',job=j)
    def test_export_cannot_mix_tenants(self):
        self.call('oak-owner','export_create',403,tenant='oak',ids=['oak-payroll','elm-payroll'])
    def test_export_read_and_export_both_required(self):
        self.deny('oak-editor',['read'],'oak-payroll')
        self.call('oak-editor','export_create',403,tenant='oak',ids=['oak-payroll'])
    def test_state_survives_restart(self):
        g=self.grant();self.call('oak-owner','write',tenant='oak',id='oak-payroll',body='persisted')
        self.call('oak-owner','revoke',tenant='oak',grant=g['grant']);self.stop();self.start()
        self.assertEqual(self.read()['body'],'persisted');self.read(g['principal'],expected=403)
    def test_cyclic_grant_fails_closed(self):
        f=copy.deepcopy(self.fixture)
        for p,parent in [('loop-a','loop-b'),('loop-b','loop-a')]:
            f['principals'][p]={'kind':'service','active':True,'grant':p}
            f['grants'][p]={'issuer':parent,'tenant':'oak','resource':'*','actions':['read','delegate'],'active':True}
        self.prepare(f);self.read('loop-a',expected=403)
    def test_orphaned_grant_fails_closed(self):
        f=copy.deepcopy(self.fixture)
        f['principals']['orphan']={'kind':'service','active':True,'grant':'missing'}
        self.prepare(f);self.read('orphan',expected=403)
    def test_inactive_ancestor_fails_closed(self):
        f=copy.deepcopy(self.fixture)
        f['principals']['worker']={'kind':'service','active':True,'grant':'g'}
        f['grants']['g']={'issuer':'suspended','tenant':'oak','resource':'*','actions':['read'],'active':True}
        self.prepare(f);self.read('worker',expected=403)
    def test_owner_can_revoke_another_issuers_grant(self):
        self.call('oak-owner','membership',tenant='oak',principal='oak-editor',role='owner')
        g=self.grant('oak-editor')
        self.call('oak-owner','revoke',tenant='oak',grant=g['grant']);self.read(g['principal'],expected=403)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--app',type=Path,required=True)
    args=parser.parse_args();APP=args.app.resolve()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Contract))
    print(json.dumps({'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'reward':int(result.wasSuccessful())}))
    raise SystemExit(not result.wasSuccessful())
