"""Versioned, evidence-weighted triage. Scores are policy points, not probabilities."""
import re

SAFE_GREEN = '#4ade80'
SUSPICIOUS_RED = '#ff6b6b'
POLICY_VERSION = 4
SUSPICIOUS_THRESHOLD = 5
SAFE_MAX_SCORE = 1.5
# Related observations count at most once per family in each message. Repeating
# the same link/header cannot inflate the verdict; severe evidence cannot be offset.
WEIGHTS = {
    'attachment_executable_extension': ('dangerous_file', 8),
    'attachment_double_extension': ('dangerous_file', 8),
    'attachment_direction_controls': ('dangerous_file', 8),
    'attachment_active_content_extension': ('active_file', 5),
    'url_embedded_credentials': ('deceptive_url', 5),
    'link_display_target_mismatch': ('link_mismatch', 3),
    'url_ip_address': ('link_structure', 2),
    'reply_to_domain_mismatch': ('reply_identity', 1),
    'sender_missing_or_ambiguous': ('sender_identity', 3),
    'reported_authentication_failure': ('unverified_auth', 1),
    'reply_to_unparseable': ('reply_identity', 1),
    'url_unencrypted_http': ('transport', .5),
    'url_internationalized_domain': ('internationalized_domain', .5),
    'url_malformed': ('message_quality', .5),
    'mime_parser_defects': ('message_quality', .5),
    'attachment_archive': ('uninspected_archive', 1),
}
HARD_WARNINGS = {'attachment_executable_extension', 'attachment_double_extension',
                 'attachment_direction_controls', 'attachment_active_content_extension',
                 'url_embedded_credentials'}
SAFE_BLOCKERS = {'sender_missing_or_ambiguous', 'reply_to_unparseable', 'url_malformed',
                 'mime_parser_defects', 'attachment_archive', 'url_ip_address',
                 'link_display_target_mismatch'}
# Independently block an AI benign classification on direct sensitive requests.
# General survey deadlines and words such as "AI" or "anonymous" are not signals.
REQUEST = re.compile(r'\b(?:send|share|provide|enter|submit|reply\s+with)\b[^.!?\n]{0,70}\b(?:password|passcode|one[- ]time\s+(?:code|password)|mfa\s+code|otp|recovery\s+code|seed\s+phrase)\b', re.I)
PAYMENT = re.compile(r'\b(?:change|changed|new|updated|replace|replacement)\b[^.!?\n]{0,60}\b(?:bank\s+(?:account|details)|payment\s+(?:details|instructions)|wire\s+instructions)\b', re.I)
INJECTION = re.compile(r'\b(?:ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions|(?:mark|classify)\s+(?:this\s+(?:email|message)\s+)?(?:as\s+)?safe\s+regardless)\b', re.I)


def content_signals(item):
    text = item.get('body_text', '') + '\n' + item.get('alternative_body_text', '')
    signals = {}
    for match in REQUEST.finditer(text):
        prefix = text[max(0,match.start()-45):match.start()].lower()
        if re.search(r"(?:do not|don't|never|will not|won't|avoid)\s+(?:\w+\s+){0,4}$", prefix):
            continue
        signals['sensitive_request'] = 6
        break
    if PAYMENT.search(text):
        signals['payment_change'] = 3
    if INJECTION.search(text):
        signals['embedded_instructions'] = 6
    return signals


def evaluate(items, report=None):
    report = report or {}
    ai = report.get('ai_analysis', {})
    result = ai.get('result', {}) if ai.get('status') == 'completed' else {}
    verdict, confidence = result.get('verdict'), result.get('confidence')
    reliable_ai = confidence in ('medium', 'high')
    message_scores = []
    evidence = []
    blockers = set()
    hard = False
    for index, (_, item) in enumerate(items, 1):
        families = {}
        resource_only = set(item.get('resource_urls', [])) - set(item.get('navigation_urls', []))
        for finding in item.get('assessment', {}).get('findings', []):
            code = finding.get('code')
            if code == 'url_unencrypted_http' and finding.get('evidence') in resource_only:
                continue
            if code in WEIGHTS:
                family, weight = WEIGHTS[code]
                families[family] = max(families.get(family, 0), weight)
            elif finding.get('priority') in ('medium','high'):
                # Future unknown checks must not silently become a benign result.
                blockers.add('unrecognized_warning')
                families['other_warning'] = max(families.get('other_warning', 0), 3)
            hard |= code in HARD_WARNINGS or finding.get('priority') == 'high'
            if code in SAFE_BLOCKERS:
                blockers.add(code)
        local = content_signals(item)
        families.update(local)
        if local:
            blockers.update(local)
        hard |= local.get('sensitive_request', 0) >= 6 or local.get('embedded_instructions', 0) >= 6
        message_scores.append(sum(families.values()))
        evidence.extend({'message': index, 'family': family, 'points': points}
                        for family, points in sorted(families.items()))
    # Do not combine harmless weak clues across unrelated attached originals.
    score = max(message_scores, default=0)
    if reliable_ai and (verdict in ('likely_phishing', 'likely_spam') or result.get('risk_signals')):
        score = max(score, 6)
        evidence.append({'message': 'all', 'family': 'ai_adverse_context', 'points': 6})
    action = 'Verify the request with the sender through a known contact method. If unsure, forward it to Security.'
    reason = 'There is not enough consistent evidence to conclude whether this email is legitimate.'
    label, color = 'SUSPICIOUS', SUSPICIOUS_RED
    basis = []
    complete = (ai.get('coverage_complete') is True and ai.get('original_attached') is True
                and bool(report.get('originals'))
                and all(item.get('assessment') and item.get('body_text', '').strip()
                        and not item.get('body_truncated') and not item.get('alternative_body_truncated') for _,item in items))
    sensitive_action = result.get('requested_action') in (
        'credentials_or_mfa', 'payment_or_bank_change', 'sensitive_data', 'download_or_execute')
    if hard or score >= SUSPICIOUS_THRESHOLD:
        label, color = 'SUSPICIOUS', SUSPICIOUS_RED
        families_seen = {signal['family'] for signal in evidence}
        if 'sensitive_request' in families_seen:
            reason = 'The message requests a password, MFA code or similar secret. That request needs Security review.'
        elif 'embedded_instructions' in families_seen:
            reason = 'The message contains instructions aimed at manipulating the email analyzer. That is a warning requiring review.'
        elif families_seen & {'dangerous_file', 'active_file'}:
            reason = 'An attachment filename indicates executable, active or disguised content. The file has not been malware-scanned.'
        elif 'deceptive_url' in families_seen:
            reason = 'A link contains user information before its real hostname, which can disguise the destination.'
        elif 'ai_adverse_context' in families_seen:
            reason = 'AI analysis identified phishing, unwanted bulk email or concrete risk indicators in the message.'
        else:
            reason = 'Several independent warning signals together require review.'
        reason += ' This is not confirmation of spam or phishing.'
        action = 'Avoid links and attachments. Forward this report and the original email to Security for review.'
        basis.append('strong_or_combined_risk')
    elif (reliable_ai and verdict == 'likely_legitimate' and complete
          and score <= SAFE_MAX_SCORE and not blockers and not sensitive_action):
        label, color = 'SAFE', SAFE_GREEN
        reason = 'The content and requested action are consistent with a legitimate email, with no material warning signs in the available evidence.'
        action = 'No suspicious action was identified. Independently verify unexpected requests for payments, credentials or sensitive changes.'
        basis.append('legitimate_context_supported')
        if any(f['family']=='unverified_auth' for f in evidence):
            reason += ' An unverified authentication-failure claim was weighed as a weak clue, not proof of spoofing.'
        else:
            reason += ' Missing authentication headers alone do not make an email suspicious.'
    else:
        if ai.get('status') != 'completed':
            basis.append('ai_unavailable')
            reason = 'AI analysis was unavailable, so this report needs manual review before it can be assessed as Safe.'
        elif not complete:
            basis.append('incomplete_original_evidence')
            reason = 'Essential original-email evidence is missing or incomplete. Manual review is required before treating this report as Safe.'
        elif not reliable_ai:
            basis.append('low_ai_confidence')
            reason = 'The assessment has low confidence. This report needs manual review before it can be assessed as Safe.'
        elif blockers or sensitive_action or score > SAFE_MAX_SCORE:
            basis.append('unresolved_material_evidence')
            reason = 'Some evidence or a sensitive requested action needs independent verification before a Safe assessment.'
        else:
            basis.append('inconclusive_context')
            reason = 'The available evidence does not support a Safe assessment. Review is required; this is not confirmation of malicious activity.'
        action = 'Verify the request through a known contact method before acting. Forward this report and the original email to Security if you need further review.'
    return {'policy_version': POLICY_VERSION, 'result': label, 'color': color,
            'reason': reason, 'action': action, 'risk_points': score,
            'suspicious_threshold': SUSPICIOUS_THRESHOLD, 'safe_max_points': SAFE_MAX_SCORE,
            'decision_basis': basis, 'weighted_signals': evidence,
            'safe_blockers': sorted(blockers), 'original_coverage_complete': complete}


def combine(items, report=None):
    decision = evaluate(items, report)
    return tuple(decision[key] for key in ('result','color','reason','action'))


def ai_notes(report):
    ai = report.get('ai_analysis', {})
    if not ai:
        return ['Offline checks only. AI analysis was not performed.']
    if ai.get('status') != 'completed':
        return ['AI analysis unavailable. This result uses offline checks only.']
    result = ai.get('result', {})
    notes = ['AI-assisted assessment. The final result weighs content, requested actions and offline evidence.',
             'AI summary: ' + str(result.get('summary', ''))]
    notes.extend('AI finding: ' + str(reason) for reason in result.get('reasons', [])[:4])
    if ai.get('coverage_complete') is not True:
        notes.append('Some material evidence was unavailable or shortened. Manual review is needed.')
    elif ai.get('metadata_notes'):
        notes.append('Some unverified header metadata was shortened; material message content was available.')
    return notes


def decision_record(report):
    def walk(items):
        for item in items:
            yield ('Original', item)
            yield from walk(item.get('originals', []))
    items = list(walk(report.get('originals', []))) or [('Submitted', report)]
    record = evaluate(items, report)
    record.pop('color')
    return record
