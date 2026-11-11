package com.ghost.verify

import com.google.gson.Gson
import org.junit.Assert.*
import org.junit.Test

class RestoreAuditModelTest {
    private val pkg = "com.ghost.verify"
    private fun response(extra: String = "") = GhostCallParser.parse(
        """{"ok":true,"pkg":"$pkg","process":"$pkg","layer":"L3","deviceId":"restored-test",$extra"expected":{"build.model":"CONFIG_ONLY_SENTINEL"}}""")

    @Test fun requiresRosterMembershipAndCorrectProcess() {
        val adopted = RestoreAuditState.fromResponses("[\"$pkg\"]", response(), pkg, pkg)
        assertEquals("ok", adopted.status)
        assertTrue(adopted.adopted)
        assertEquals("restored-test", adopted.deviceId)
        val unadopted = RestoreAuditState.fromResponses("[]", response(), pkg, pkg)
        assertFalse(unadopted.adopted)
        val wrongProcess = RestoreAuditState.fromResponses("[\"$pkg\"]", response(), pkg, "$pkg:other")
        assertEquals("unavailable", wrongProcess.status)
    }

    @Test fun missingOrUnsupportedEvidenceCannotProveAdoption() {
        assertEquals("unavailable", RestoreAuditState.fromResponses(null, response(), pkg, pkg).status)
        val unsupported = GhostCallResult.Unsupported("Method not found: expectedEnv")
        assertEquals("unavailable", RestoreAuditState.fromResponses("[\"$pkg\"]", unsupported, pkg, pkg).status)
        val noId = GhostCallParser.parse("""{"ok":true,"pkg":"$pkg","process":"$pkg","layer":"L3"}""")
        assertEquals("unavailable", RestoreAuditState.fromResponses("[\"$pkg\"]", noId, pkg, pkg).status)
    }

    @Test fun evidenceSerializationNeverCopiesExpectedValues() {
        val roster = Gson().toJson("[\"$pkg\"]")
        val state = RestoreAuditState.fromResponses(roster, response(), pkg, pkg)
        val context = RestoreAuditContext("synthetic-run", 100, 200, state, state)
        val json = Gson().toJson(context)
        assertTrue(state.adopted)
        assertFalse(json.contains("CONFIG_ONLY_SENTINEL"))
        assertFalse(json.contains("expected"))
        assertEquals("restored-test", Gson().fromJson(json, RestoreAuditContext::class.java).before.deviceId)
    }
}
