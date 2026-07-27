# aivss_engine.py
# Core OWASP AIVSS v4 Engine for ANTIGRAVITY SHIELD XDR

INDUSTRIES = {
    "1": {
        "id": "1",
        "name": "General",
        "name_th": "ทั่วไป (General)",
        "description": "Standard AIVSS spec weights — suitable for any AI system",
        "regulations": "General AI security best practices",
        "w1": 0.30, "w2": 0.50, "w3": 0.20,
        "mitigation_levels": [
            {"desc": "Strong mitigation in place", "desc_th": "มีการลดความเสี่ยงระดับดีเยี่ยม", "val": 1.00},
            {"desc": "Partial mitigation", "desc_th": "มีการลดความเสี่ยงบางส่วน", "val": 1.20},
            {"desc": "Minimal / weak mitigation", "desc_th": "มีการลดความเสี่ยงเล็กน้อย/ไม่เสถียร", "val": 1.35},
            {"desc": "No mitigation — fully exploitable", "desc_th": "ไม่มีการลดความเสี่ยงใดๆ", "val": 1.50},
        ],
    },
    "2": {
        "id": "2",
        "name": "Financial Services",
        "name_th": "การเงินและการธนาคาร (Financial Services)",
        "description": "Fraud detection, algorithmic trading, credit scoring, AML/KYC",
        "regulations": "GDPR, CCPA, GLBA, SOX, Fair Lending Laws",
        "w1": 0.25, "w2": 0.60, "w3": 0.15,
        "mitigation_levels": [
            {"desc": "Strong mitigation — mature security program", "desc_th": "การป้องกันเข้มข้นและครบถ้วน", "val": 1.00},
            {"desc": "Moderate mitigation", "desc_th": "การป้องกันระดับปานกลาง", "val": 1.10},
            {"desc": "Weak / no mitigation", "desc_th": "ไม่มีการป้องกันหรืออ่อนแอมาก", "val": 1.30},
        ],
    },
    "3": {
        "id": "3",
        "name": "Healthcare",
        "name_th": "การแพทย์และสาธารณสุข (Healthcare)",
        "description": "Diagnostics, patient monitoring, drug discovery, PHI processing",
        "regulations": "HIPAA, GDPR, FDA AI/ML guidance, Belmont Report",
        "w1": 0.20, "w2": 0.50, "w3": 0.30,
        "mitigation_levels": [
            {"desc": "Strong mitigation", "desc_th": "การควบคุมความเสี่ยงระดับสูง", "val": 1.00},
            {"desc": "Moderate mitigation", "desc_th": "การควบคุมความเสี่ยงระดับปานกลาง", "val": 1.20},
            {"desc": "Weak / no mitigation", "desc_th": "การควบคุมความเสี่ยงไม่ผ่านเกณฑ์", "val": 1.40},
        ],
    },
    "4": {
        "id": "4",
        "name": "Critical Infrastructure",
        "name_th": "โครงสร้างพื้นฐานสำคัญ (Critical Infrastructure)",
        "description": "Power grids, water systems, nuclear, oil & gas, industrial control",
        "regulations": "NERC CIP, IEC 62443, NIST CSF, Presidential Policy Directive 21",
        "w1": 0.35, "w2": 0.45, "w3": 0.20,
        "mitigation_levels": [
            {"desc": "Strong mitigation", "desc_th": "การป้องกันระดับสูงมาก", "val": 1.00},
            {"desc": "Moderate mitigation", "desc_th": "การป้องกันระดับปานกลาง", "val": 1.20},
            {"desc": "Minimal mitigation", "desc_th": "การป้องกันระดับต่ำสุด", "val": 1.40},
            {"desc": "No mitigation — critical exposure", "desc_th": "ไม่มีระบบการทำงานร่วมในการลดความเสี่ยง", "val": 1.50},
        ],
    },
    "5": {
        "id": "5",
        "name": "Automotive / Transportation",
        "name_th": "ยานยนต์และการขนส่ง (Automotive / Transport)",
        "description": "Autonomous vehicles, ADAS, traffic management, fleet AI",
        "regulations": "ISO 26262, SOTIF (ISO 21448), UN R155/R156, SAE J3016",
        "w1": 0.20, "w2": 0.45, "w3": 0.35,
        "mitigation_levels": [
            {"desc": "Strong mitigation — certified systems", "desc_th": "ผ่านการตรวจสอบมาตรฐานความปลอดภัยขั้นสูง", "val": 1.00},
            {"desc": "Moderate mitigation", "desc_th": "มีความยืดหยุ่นในการควบคุมระดับปานกลาง", "val": 1.20},
            {"desc": "Minimal mitigation", "desc_th": "การป้องกันจำกัดเฉพาะเรื่อง", "val": 1.40},
            {"desc": "No mitigation — safety critical exposure", "desc_th": "มีความเสี่ยงสูงต่อความปลอดภัยและระบบควบคุม", "val": 1.50},
        ],
    },
    "6": {
        "id": "6",
        "name": "Legal / Justice",
        "name_th": "กฎหมายและกระบวนการยุติธรรม (Legal / Justice)",
        "description": "Predictive policing, sentencing/parole AI, case prediction, eDiscovery",
        "regulations": "GDPR, EU AI Act (High-Risk), Civil Rights Laws, Due Process",
        "w1": 0.20, "w2": 0.45, "w3": 0.35,
        "mitigation_levels": [
            {"desc": "Strong mitigation", "desc_th": "การลดความเสี่ยงระดับดีเยี่ยม", "val": 1.00},
            {"desc": "Moderate mitigation", "desc_th": "การลดความเสี่ยงระดับปานกลาง", "val": 1.20},
            {"desc": "Minimal mitigation", "desc_th": "การลดความเสี่ยงเล็กน้อย", "val": 1.40},
            {"desc": "No mitigation", "desc_th": "ไม่มีมาตรการเยียวยาใดๆ", "val": 1.50},
        ],
    },
    "7": {
        "id": "7",
        "name": "Government / Public Sector",
        "name_th": "ภาครัฐและบริการสาธารณะ (Government / Public)",
        "description": "Citizen services, benefits determination, border control, public safety AI",
        "regulations": "GDPR, EU AI Act, OMB AI Guidance, FedRAMP, Privacy Act",
        "w1": 0.25, "w2": 0.50, "w3": 0.25,
        "mitigation_levels": [
            {"desc": "Strong mitigation", "desc_th": "ความพร้อมรับมือระดับสูงสุด", "val": 1.00},
            {"desc": "Moderate mitigation", "desc_th": "ความพร้อมรับมือระดับดี", "val": 1.15},
            {"desc": "Minimal mitigation", "desc_th": "ความพร้อมรับมือระดับจำกัด", "val": 1.35},
            {"desc": "No mitigation", "desc_th": "ไม่มีความพร้อมในการรับมือ", "val": 1.50},
        ],
    },
}

AV_OPTIONS = [
    {"key": "1", "desc": "Network (0.85)", "desc_th": "เครือข่ายอินเทอร์เน็ต (0.85)", "val": 0.85},
    {"key": "2", "desc": "Adjacent Network (0.62)", "desc_th": "เครือข่ายท้องถิ่นวงเดียวกัน (0.62)", "val": 0.62},
    {"key": "3", "desc": "Local (0.55)", "desc_th": "เข้าถึงโดยตรงบนเครื่องเครื่อง (0.55)", "val": 0.55},
    {"key": "4", "desc": "Physical (0.20)", "desc_th": "การสัมผัสอุปกรณ์จริง (0.20)", "val": 0.20},
]

AC_OPTIONS = [
    {"key": "1", "desc": "Low (0.77)", "desc_th": "ต่ำ (0.77)", "val": 0.77},
    {"key": "2", "desc": "High (0.44)", "desc_th": "สูง (0.44)", "val": 0.44},
]

PR_OPTIONS = [
    {"key": "1", "desc": "None (0.85)", "desc_th": "ไม่มีเลย (0.85)", "val": 0.85},
    {"key": "2", "desc": "Low (0.62)", "desc_th": "ระดับสิทธิ์ผู้ใช้ทั่วไป (0.62)", "val": 0.62},
    {"key": "3", "desc": "High (0.27)", "desc_th": "ระดับสิทธิ์ผู้ดูแลระบบ (0.27)", "val": 0.27},
]

UI_OPTIONS = [
    {"key": "1", "desc": "None (0.85)", "desc_th": "ไม่ต้องมี (0.85)", "val": 0.85},
    {"key": "2", "desc": "Required (0.62)", "desc_th": "ต้องการการปฏิสัมพันธ์จากผู้ใช้ (0.62)", "val": 0.62},
]

S_OPTIONS = [
    {"key": "1", "desc": "Unchanged (1.00)", "desc_th": "ขอบเขตเท่าเดิม (1.00)", "val": 1.00},
    {"key": "2", "desc": "Changed (1.50)", "desc_th": "ขอบเขตเปลี่ยนข้ามระบบ (1.50)", "val": 1.50},
]

MODEL_COMPLEXITY_OPTIONS = [
    {"key": "1", "desc": "Simple — narrow, rule-based model (1.00)", "desc_th": "ระบบกฎเกณฑ์ / โครงสร้างง่ายๆ (1.00)", "val": 1.00},
    {"key": "2", "desc": "Moderate — standard ML model (1.20)", "desc_th": "โมเดล Machine Learning ทั่วไป (1.20)", "val": 1.20},
    {"key": "3", "desc": "Complex — deep network (1.35)", "desc_th": "เครือข่ายประสาทเทียม Deep Learning (1.35)", "val": 1.35},
    {"key": "4", "desc": "Highly Complex — frontier LLM / agentic AI (1.50)", "desc_th": "Frontier LLM / ระบบ AI แบบอัตโนมัติ (1.50)", "val": 1.50},
]

# Severity for AI Specific Subcategories
SEVERITY_OPTIONS = [
    {"key": "1", "desc": "Critical (0.90)", "desc_th": "วิกฤต (0.90)", "val": 0.90},
    {"key": "2", "desc": "High (0.70)", "desc_th": "สูง (0.70)", "val": 0.70},
    {"key": "3", "desc": "Medium (0.50)", "desc_th": "ปานกลาง (0.50)", "val": 0.50},
    {"key": "4", "desc": "Low (0.20)", "desc_th": "ต่ำ (0.20)", "val": 0.20},
    {"key": "5", "desc": "None (0.00)", "desc_th": "ไม่มีเลย (0.00)", "val": 0.00},
]

IMPACT_OPTIONS = [
    {"key": "1", "desc": "None (0.00)", "desc_th": "ไม่มีผลกระทบ (0.00)", "val": 0.00},
    {"key": "2", "desc": "Low (0.22)", "desc_th": "กระทบเล็กน้อย (0.22)", "val": 0.22},
    {"key": "3", "desc": "Medium (0.55)", "desc_th": "กระทบปานกลาง (0.55)", "val": 0.55},
    {"key": "4", "desc": "High (0.85)", "desc_th": "กระทบสูง (0.85)", "val": 0.85},
    {"key": "5", "desc": "Critical (1.00)", "desc_th": "กระทบระดับวิกฤต (1.00)", "val": 1.00},
]

EXPLOITABILITY_OPTIONS = [
    {"key": "X", "desc": "Not Defined (1.00)", "desc_th": "ไม่ได้ระบุ (1.00)", "val": 1.00},
    {"key": "1", "desc": "Unproven (0.90)", "desc_th": "ยังไม่มีรายงานการทุจริตจริง (0.90)", "val": 0.90},
    {"key": "2", "desc": "Proof-of-Concept (0.95)", "desc_th": "มีโค้ดตัวอย่างการทุจริต (0.95)", "val": 0.95},
    {"key": "3", "desc": "Functional (1.00)", "desc_th": "ใช้งานเจาะระบบได้จริง (1.00)", "val": 1.00},
    {"key": "4", "desc": "High (1.00)", "desc_th": "โจมตีระบบแพร่หลาย (1.00)", "val": 1.00},
]

REMEDIATION_LEVEL_OPTIONS = [
    {"key": "X", "desc": "Not Defined (1.00)", "desc_th": "ไม่ได้ระบุ (1.00)", "val": 1.00},
    {"key": "1", "desc": "Official Fix available (0.95)", "desc_th": "มีแพตช์อัปเดตอย่างเป็นทางการ (0.95)", "val": 0.95},
    {"key": "2", "desc": "Temporary Fix available (0.96)", "desc_th": "มีวิธีแก้ไขชั่วคราว (0.96)", "val": 0.96},
    {"key": "3", "desc": "Workaround available (0.97)", "desc_th": "มีทางเลี่ยงการใช้งาน (0.97)", "val": 0.97},
    {"key": "4", "desc": "Unavailable — no fix exists (1.00)", "desc_th": "ไม่มีตัวแก้ไขใดๆ เลย (1.00)", "val": 1.00},
]

REPORT_CONFIDENCE_OPTIONS = [
    {"key": "X", "desc": "Not Defined (1.00)", "desc_th": "ไม่ได้ระบุ (1.00)", "val": 1.00},
    {"key": "1", "desc": "Unknown — unconfirmed report (0.92)", "desc_th": "ยังไม่มีข้อมูลยืนยันชัดเจน (0.92)", "val": 0.92},
    {"key": "2", "desc": "Reasonable — corroborated (0.96)", "desc_th": "มีความน่าเชื่อถือในรายงาน (0.96)", "val": 0.96},
    {"key": "3", "desc": "Confirmed — vendor-confirmed (1.00)", "desc_th": "ได้รับการยืนยันอย่างเป็นทางการ (1.00)", "val": 1.00},
]

ENV_REQ_OPTIONS = [
    {"key": "X", "desc": "Not Defined — inherits base (1.00)", "desc_th": "ค่าเริ่มต้นเท่าของเดิม (1.00)", "val": 1.00},
    {"key": "1", "desc": "Low requirement (0.50)", "desc_th": "ความจำเป็นต่ำ (0.50)", "val": 0.50},
    {"key": "2", "desc": "Medium requirement (1.00)", "desc_th": "ความจำเป็นปานกลาง (1.00)", "val": 1.00},
    {"key": "3", "desc": "High requirement (1.50)", "desc_th": "ความจำเป็นสูงมาก (1.50)", "val": 1.50},
]

ENV_MULTIPLIER_OPTIONS = [
    {"key": "1", "desc": "None (0.00)", "desc_th": "ไม่มีปัจจัยเร่งสิ่งแวดล้อม (0.00)", "val": 0.00},
    {"key": "2", "desc": "Low (0.05)", "desc_th": "สิ่งแวดล้อมขยายความเสี่ยงต่ำ (0.05)", "val": 0.05},
    {"key": "3", "desc": "Medium (0.15)", "desc_th": "สิ่งแวดล้อมขยายความเสี่ยงปานกลาง (0.15)", "val": 0.15},
    {"key": "4", "desc": "High (0.30)", "desc_th": "สิ่งแวดล้อมขยายความเสี่ยงสูง (0.30)", "val": 0.30},
]

AI_SUBCATEGORIES = [
    {
        "code": "MR", 
        "name": "Model Robustness", 
        "name_th": "ความแข็งแกร่งของโมเดล",
        "subcats": ["Evasion Resistance", "Gradient Masking / Obfuscation", "Robustness Certification"]
    },
    {
        "code": "DS", 
        "name": "Data Sensitivity", 
        "name_th": "ความอ่อนไหวของข้อมูลนำเข้า",
        "subcats": ["Data Confidentiality", "Data Integrity", "Data Provenance"]
    },
    {
        "code": "EI", 
        "name": "Ethical Implications", 
        "name_th": "ผลกระทบเชิงจริยธรรม",
        "subcats": ["Bias and Discrimination", "Transparency and Explainability", "Accountability", "Societal Impact"]
    },
    {
        "code": "DC", 
        "name": "Decision Criticality", 
        "name_th": "ความวิกฤตของการสั่งการ",
        "subcats": ["Safety-Critical Applications", "Financial Impact", "Reputational Damage", "Operational Disruption"]
    },
    {
        "code": "AD", 
        "name": "Adaptability", 
        "name_th": "ความสามารถในการปรับตัวและทนทาน",
        "subcats": ["Continuous Monitoring", "Retraining Capabilities", "Threat Intelligence Integration", "Adversarial Training"]
    },
    {
        "code": "AA", 
        "name": "Adversarial Attack Surface", 
        "name_th": "ช่องทางโจมตีผ่านตัวแปรแวดล้อม",
        "subcats": ["Model Inversion", "Model Extraction", "Membership Inference"]
    },
    {
        "code": "LL", 
        "name": "Lifecycle Vulnerabilities", 
        "name_th": "ช่องโหว่ตลอดวัฏจักรโมเดล",
        "subcats": ["Development Security", "Training Security", "Deployment Security", "Operational Security"]
    },
    {
        "code": "GV", 
        "name": "Governance and Validation", 
        "name_th": "ธรรมาภิบาลและการพิสูจน์ยืนยัน",
        "subcats": ["Regulatory Compliance", "Auditing", "Risk Management", "Human Oversight", "Ethical Framework Alignment"]
    },
    {
        "code": "CS", 
        "name": "Cloud / LLM Security (CSA Taxonomy)", 
        "name_th": "ความปลอดภัย Cloud และ LLM",
        "subcats": [
            "Model Manipulation / Prompt Injection", "Data Poisoning", "Sensitive Data Disclosure",
            "Model Stealing", "Failure / Malfunctioning", "Insecure Supply Chain",
            "Insecure Apps / Plugins", "Denial of Service (DoS)", "Loss of Governance / Compliance"
        ]
    }
]

PRESETS = {
    "hybrid_ensemble": {
        "name": "Antigravity Hybrid Ensemble XDR Engine",
        "name_th": "เอนจินตรวจจับวิเคราะห์ทราฟฟิกเครือข่าย XDR",
        "industry_id": "1",
        "av": 0.85, # Network
        "ac": 0.44, # High Complexity
        "pr": 0.27, # High Privileges Required
        "ui": 0.85, # UI None
        "s": 1.00,  # Scope Unchanged
        "mav": None, "mac": None, "mpr": None, "mui": None, "ms": None,
        "ai_metrics": {
            "MR": [0.50, 0.50, 0.20], # Medium anomaly evasion, Low certification
            "DS": [0.20, 0.50, 0.50], # Low PII, medium data stream integrity
            "EI": [0.00, 0.20, 0.20, 0.00], # Virtually no ethical bias concerns in packets
            "DC": [0.50, 0.20, 0.50, 0.50], # Dynamic containment block can disrupt network
            "AD": [0.50, 0.50, 0.50, 0.20], # Decent logging and retraining
            "AA": [0.50, 0.50, 0.20],
            "LL": [0.20, 0.20, 0.20, 0.50],
            "GV": [0.50, 0.50, 0.50, 0.50, 0.50],
            "CS": [0.20, 0.50, 0.20, 0.20, 0.50, 0.20, 0.20, 0.50, 0.20]
        },
        "mc": 1.20, # Moderate ML
        "c": 0.22, "i": 0.55, "a": 0.55, "si": 0.00, # Primarily impacts integrity & availability
        "e": 0.90, "rl": 0.95, "rc": 1.00, # Theoretical, workaround exists, confirmed
        "cr": 1.00, "ir": 1.00, "ar": 1.00, "sir": 1.00,
        "env_mult": 0.00,
        "mitigation": 1.00 # Strong mitigation in place
    },
    "llm_chatbot": {
        "name": "Customer Support LLM Chatbot (Frontier LLM)",
        "name_th": "แชตบอตบริการลูกค้าขับเคลื่อนด้วย LLM",
        "industry_id": "7",
        "av": 0.85, # Network
        "ac": 0.77, # Low complexity attack (prompt injection)
        "pr": 0.85, # None required
        "ui": 0.62, # Required (tricking human user)
        "s": 1.50,  # Changed (escalate to internal db)
        "mav": None, "mac": None, "mpr": None, "mui": None, "ms": None,
        "ai_metrics": {
            "MR": [0.70, 0.70, 0.50],
            "DS": [0.70, 0.50, 0.50],
            "EI": [0.50, 0.50, 0.50, 0.50],
            "DC": [0.20, 0.50, 0.70, 0.50],
            "AD": [0.20, 0.20, 0.20, 0.20],
            "AA": [0.70, 0.50, 0.70],
            "LL": [0.50, 0.50, 0.50, 0.50],
            "GV": [0.50, 0.20, 0.50, 0.50, 0.50],
            "CS": [0.90, 0.70, 0.70, 0.50, 0.50, 0.50, 0.70, 0.50, 0.50]
        },
        "mc": 1.50, # Frontier LLM
        "c": 0.55, "i": 0.55, "a": 0.22, "si": 0.55,
        "e": 1.00, "rl": 1.00, "rc": 1.00,
        "cr": 1.00, "ir": 1.00, "ar": 1.00, "sir": 1.00,
        "env_mult": 0.05,
        "mitigation": 1.20 # Partial mitigation
    }
}

def calculate_aivss_score_logic(params):
    """
    Computes AIVSS score using the OWASP AIVSS v4 specifications.
    """
    industry_id = params.get("industry_id", "1")
    industry = INDUSTRIES.get(industry_id, INDUSTRIES["1"])
    w1, w2, w3 = industry["w1"], industry["w2"], industry["w3"]
    
    # 1. Base Score
    av = float(params.get("av", 0.85))
    ac = float(params.get("ac", 0.77))
    pr = float(params.get("pr", 0.85))
    ui = float(params.get("ui", 0.85))
    s = float(params.get("s", 1.00))
    base_score = min(10.0, av * ac * pr * ui * s)
    
    # 2. Modified Base Score
    mav = params.get("mav")
    mac = params.get("mac")
    mpr = params.get("mpr")
    mui = params.get("mui")
    ms = params.get("ms")
    
    mav_val = float(mav) if mav is not None else av
    mac_val = float(mac) if mac is not None else ac
    mpr_val = float(mpr) if mpr is not None else pr
    mui_val = float(mui) if mui is not None else ui
    ms_val = float(ms) if ms is not None else s
    modified_base_score = min(10.0, mav_val * mac_val * mpr_val * mui_val * ms_val)
    
    # 3. AI-Specific score (multiply averages of categories)
    metric_scores = {}
    ai_metrics_input = params.get("ai_metrics", {})
    
    for item in AI_SUBCATEGORIES:
        code = item["code"]
        subcats = item["subcats"]
        scores = ai_metrics_input.get(code, [])
        if not scores:
            scores = [0.0] * len(subcats)
        avg = sum(scores) / len(scores)
        metric_scores[code] = avg
        
    mc = float(params.get("mc", 1.0))
    
    # Multiply all AI sub-scores
    ai_score_product = 1.0
    for code in metric_scores:
        ai_score_product *= metric_scores[code]
        
    ai_score = ai_score_product * mc
    
    # 4. Impact Score
    c = float(params.get("c", 0.0))
    i = float(params.get("i", 0.0))
    a = float(params.get("a", 0.0))
    si = float(params.get("si", 0.0))
    impact_score = (c + i + a + si) / 4.0
    
    # 5. Temporal Score
    e = float(params.get("e", 1.0))
    rl = float(params.get("rl", 1.0))
    rc = float(params.get("rc", 1.0))
    temporal_score = (e + rl + rc) / 3.0
    
    # 6. Environmental requirement
    cr = float(params.get("cr", 1.0))
    ir = float(params.get("ir", 1.0))
    ar = float(params.get("ar", 1.0))
    sir = float(params.get("sir", 1.0))
    env_mult = float(params.get("env_mult", 0.0))
    
    env_component = (cr * ir * ar * sir) * ai_score
    env_score = min(10.0, ((modified_base_score + env_component) * temporal_score) * (1.0 + env_mult))
    
    # 7. Mitigation
    mitigation = float(params.get("mitigation", 1.0))
    
    # 8. AIVSS Score
    aivss_score = min(10.0, (
        (w1 * modified_base_score) +
        (w2 * ai_score) +
        (w3 * impact_score)
    ) * temporal_score * mitigation)
    
    # Severity label helper
    def get_severity(score):
        if score >= 9.0: return "CRITICAL"
        if score >= 7.0: return "HIGH"
        if score >= 4.0: return "MEDIUM"
        if score > 0.0: return "LOW"
        return "NONE"
        
    return {
        "aivss_score": round(aivss_score, 2),
        "severity": get_severity(aivss_score),
        "base_score": round(base_score, 3),
        "modified_base_score": round(modified_base_score, 3),
        "ai_score": round(ai_score, 6),
        "metric_scores": {code: round(val, 3) for code, val in metric_scores.items()},
        "impact_score": round(impact_score, 3),
        "temporal_score": round(temporal_score, 3),
        "env_score": round(env_score, 3)
    }
