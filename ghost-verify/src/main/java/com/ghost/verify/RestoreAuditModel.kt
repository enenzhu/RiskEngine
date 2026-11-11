package com.ghost.verify

/** 控制面证据只确认本轮采集的归属，expectedEnv.expected 从不进入实际观测。 */
data class RestoreAuditState(
    val status: String,
    val adopted: Boolean,
    val deviceId: String?,
) {
    companion object {
        fun fromResponses(
            rosterRaw: String?,
            response: GhostCallResult,
            pkg: String,
            process: String,
        ): RestoreAuditState {
            val roster = GhostCallParser.parseStringList(rosterRaw)
            val env = (response as? GhostCallResult.Ok)?.let { ProcessEnvModel.parseExpected(it.body) }
            val valid = roster != null && env?.pkg == pkg && env.process == process &&
                env.layer == "L3" && !env.deviceId.isNullOrBlank()
            return RestoreAuditState(
                status = if (valid) "ok" else "unavailable",
                adopted = roster?.contains(pkg) == true,
                deviceId = env?.deviceId,
            )
        }
    }
}

data class RestoreAuditContext(
    val runId: String,
    val startedAt: Long,
    val completedAt: Long,
    val before: RestoreAuditState,
    val after: RestoreAuditState,
    val schemaVersion: Int = 1,
    val dataKind: String = "live",
)
