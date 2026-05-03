class Rule:
    def __init__(self, cis_id, title, expected, check_fn, evidence_source, remediate_fn=None):
        self.cis_id = cis_id
        self.title = title
        self.expected = expected
        self.check_fn = check_fn
        self.evidence_source = evidence_source
        self.remediate_fn = remediate_fn  # NEW: función de remediación opcional

    def evaluate(self):
        try:
            current, passed = self.check_fn()
            return {
                "cis_id": self.cis_id,
                "title": self.title,
                "expected": self.expected,
                "current": current,
                "pass": passed,
                "evidence": self.evidence_source
            }
        except Exception as e:
            return {
                "cis_id": self.cis_id,
                "title": self.title,
                "expected": self.expected,
                "current": f"ERROR: {str(e)}",
                "pass": False,
                "evidence": self.evidence_source
            }

    def remediate(self):
        """
        Aplica la remediación (hardening) para esta regla.
        Retorna un dict con: cis_id, title, success (bool), message (str).
        """
        if self.remediate_fn is None:
            return {
                "cis_id": self.cis_id,
                "title": self.title,
                "success": False,
                "message": "Sin remediación automatizada disponible (manual o no implementado)"
            }
        try:
            success, message = self.remediate_fn()
            return {
                "cis_id": self.cis_id,
                "title": self.title,
                "success": success,
                "message": message
            }
        except Exception as e:
            return {
                "cis_id": self.cis_id,
                "title": self.title,
                "success": False,
                "message": f"ERROR en remediación: {str(e)}"
            }
