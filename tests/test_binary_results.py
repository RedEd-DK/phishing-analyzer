import unittest
import json

from app.ai_analysis import OpenAIAnalyzer, prepare_evidence
from app.decision import combine, decision_record, SAFE_GREEN, SUSPICIOUS_RED
from app.reply_template import html_reply, text_reply
from app.security_checks import enrich
from test_ai_analysis import cfg, report, response, result, completed, Opener


class BinaryResultTests(unittest.TestCase):
    def test_only_safe_green_or_suspicious_red(self):
        for verdict in ('likely_legitimate','likely_phishing','likely_spam','unable_to_determine'):
            for confidence in ('low','medium','high'):
                value=report(); value['ai_analysis']=completed(result(verdict,confidence))
                label,color,_,_=combine([('Original',value['originals'][0])],value)
                self.assertEqual(color,SAFE_GREEN if label=='SAFE' else SUSPICIOUS_RED)
                self.assertIn(label,{'SAFE','SUSPICIOUS'})
                for render in (html_reply,text_reply):
                    text=render(value,cfg())
                    self.assertNotIn('UNABLE TO DETERMINE',text)
                    self.assertIn(label,text)

    def test_jira_style_320_character_auth_header_does_not_make_body_incomplete(self):
        value=report(); item=value['originals'][0]
        item['subject']='Automation rule failed'
        item['body_text']='Your automation rule failed. Review the Jira audit log for details.'
        item['headers'].append({'name':'Authentication-Results','value':('mail.example; spf=fail; dmarc=fail; '+ 'x'*320)[:320]})
        enrich(value)
        payload=prepare_evidence(value,20000)
        self.assertTrue(payload['coverage_complete'])
        self.assertEqual(payload['coverage_gaps'],[])
        self.assertEqual(payload['metadata_notes'][0]['reason'],'unverified_header_metadata_shortened')
        opener=Opener(response(result(confidence='medium')))
        value['ai_analysis']=OpenAIAnalyzer(cfg(),opener).analyze(value)
        self.assertEqual(decision_record(value)['result'],'SAFE')
        text=html_reply(value,cfg())
        self.assertIn(SAFE_GREEN,text)
        self.assertIn('metadata was shortened',text)
        self.assertNotIn('Some material evidence was unavailable',text)

    def test_actual_body_omission_remains_suspicious_with_review_explanation(self):
        for change in ('parser_limit','request_limit','missing_body','missing_original','api_error'):
            value=report()
            if change=='parser_limit': value['originals'][0]['body_truncated']=True
            if change=='request_limit': value['originals'][0]['body_text']='x'*16000
            if change=='missing_body': value['originals'][0]['body_text']=''
            if change=='missing_original': value=value['originals'][0]
            value['ai_analysis']=OpenAIAnalyzer(cfg(),Opener(response())).analyze(value)
            if change=='api_error': value['ai_analysis']={'status':'unavailable'}
            decision=decision_record(value)
            self.assertEqual(decision['result'],'SUSPICIOUS')
            self.assertIn('review',decision['reason'].lower())

    def test_identity_header_clipping_is_still_material(self):
        value=report();item=value['originals'][0]
        item['headers']=[{'name':'From','value':'Display '+('x'*350)+' <sender@example.com>'}]
        payload=prepare_evidence(value,20000)
        self.assertFalse(payload['coverage_complete'])
        self.assertIn('identity_header_shortened',[gap['reason'] for gap in payload['coverage_gaps']])

    def test_many_diagnostic_headers_do_not_push_sender_out_of_payload(self):
        value=report();item=value['originals'][0]
        item['headers']=[{'name':'Authentication-Results','value':'a.test; spf=pass'} for _ in range(20)]+item['headers']
        payload=prepare_evidence(value,20000)
        self.assertEqual(payload['messages'][0]['headers_unverified'][0]['name'],'From')
        self.assertTrue(payload['coverage_complete'])
        self.assertTrue(payload['metadata_notes'])

    def test_coverage_diagnostics_stay_bounded_when_many_fields_are_omitted(self):
        value=report();item=value['originals'][0]
        item['body_text']='x'*20000;item['body_truncated']=True
        item['subject']='s'*1000
        item['headers']=[{'name':'From','value':'x'*500} for _ in range(20)]
        item['urls']=['https://example.com/'+str(i) for i in range(25)]
        item['links']=[{'text':'https://example.com','target':'https://example.com'} for _ in range(20)]
        item['attachments']=[{'name':'file.pdf'} for _ in range(20)]
        item['assessment']['findings']*=25
        value['originals']=[item]*8
        payload=prepare_evidence(value,4000)
        self.assertFalse(payload['coverage_complete'])
        self.assertLessEqual(len(json.dumps(payload,ensure_ascii=False)),4000)


if __name__=='__main__': unittest.main()
