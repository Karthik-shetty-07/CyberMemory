"""
CyberMemory AI - Automated Frontend & API Route Tests
Verifies that all 6 SOC pages and REST endpoints function correctly.
"""

import pytest
import json
from app import app, incidents_db, memory_bank_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_page_routes_status_200(client):
    """Ensure all 6 dashboard views render with HTTP 200 OK"""
    routes = [
        '/',
        '/dashboard',
        '/investigate',
        '/investigation/INC-2026-0801',
        '/history',
        '/memory',
        '/analytics'
    ]
    for route in routes:
        response = client.get(route)
        assert response.status_code == 200, f"Failed route {route} with status {response.status_code}"
        assert b"CyberMemory" in response.data

def test_dashboard_stats_api(client):
    """Test /api/dashboard/stats returns valid metrics"""
    res = client.get('/api/dashboard/stats')
    assert res.status_code == 200
    data = res.get_json()
    assert 'total_investigated' in data
    assert 'memory_items_stored' in data
    assert 'severity_breakdown' in data
    assert 'memory_growth' in data
    assert data['total_investigated'] >= 20

def test_incidents_api_and_filters(client):
    """Test incident listing and search query filtering"""
    # 1. Base list
    res = client.get('/api/incidents')
    assert res.status_code == 200
    data = res.get_json()
    assert data['total'] >= 20

    # 2. Filter by severity
    res_crit = client.get('/api/incidents?severity=Critical')
    data_crit = res_crit.get_json()
    for inc in data_crit['incidents']:
        assert inc['severity'] == 'Critical'

    # 3. Query search
    res_search = client.get('/api/incidents?query=powershell')
    data_search = res_search.get_json()
    assert data_search['total'] >= 1
    assert any('powershell' in inc['title'].lower() or 'powershell' in inc['description'].lower() for inc in data_search['incidents'])

def test_investigate_post_api(client):
    """Test running an AI investigation with Hindsight memory recall"""
    payload = {
        "title": "Automated Test Malicious Execution",
        "severity": "High",
        "alert_source": "CrowdStrike Falcon",
        "affected_host": "TEST-HOST-99",
        "user": "corp\\testuser",
        "description": "powershell.exe downloading remote payload from untrusted domain",
        "raw_logs": "EventID: 4688 powershell.exe -enc AAAA 198.51.100.44",
        "use_memory": True
    }
    res = client.post('/api/investigate', data=json.dumps(payload), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert 'incident_id' in data
    assert 'investigation' in data
    assert len(data['investigation']['investigation_steps']) > 0
    assert 'T1059.001' in data['investigation']['indicators']['mitre_techniques']

def test_feedback_submission_and_memory_retention(client):
    """Test submitting analyst feedback and retaining into Hindsight memory"""
    payload = {
        "rating": "Helpful",
        "final_outcome": "Confirmed Malicious",
        "root_cause_confirmed": "Verified phishing invoice attack",
        "comments": "Immediate isolation stopped lateral spread.",
        "retain_to_hindsight": True
    }
    res = client.post('/api/investigation/INC-2026-0801/feedback', data=json.dumps(payload), content_type='application/json')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'success'
    assert data['hindsight_retained'] is True
    assert data['retained_memory_id'] == 'MEM-INC-2026-0801'

def test_memory_search_api(client):
    """Test semantic memory search endpoint"""
    res = client.get('/api/memory/search?q=powershell')
    assert res.status_code == 200
    data = res.get_json()
    assert 'results' in data
    assert data['total_matches'] >= 1

def test_learning_analytics_api(client):
    """Test learning analytics endpoint"""
    res = client.get('/api/analytics/learning')
    assert res.status_code == 200
    data = res.get_json()
    assert 'total_memories' in data
    assert 'triage_time_reduction_percentage' in data
    assert data['triage_time_reduction_percentage'] > 70
