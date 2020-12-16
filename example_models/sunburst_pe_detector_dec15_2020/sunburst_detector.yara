rule sunburst_detector
{
    strings:
	$s0 = "OrionModuleEngineo" fullword // weight: 0.5694
	$s1 = "MakeParticipationChangeQuery" fullword // weight: 0.4271
	$s2 = "DiscoverAgentNodes" fullword // weight: 0.1424
	$s3 = "InitRescheduleEngineDiscoveryJobsTask" fullword // weight: 0.1424
	$s4 = "MaintenanceExpirationNotificationItemId" fullword // weight: 0.1424
	$s5 = "RunDatabaseMaintenace" fullword // weight: 0.1424
	$s6 = "SatelliteMatchesDefinition" fullword // weight: 0.1424
	$s7 = "moduleExpirations"  fullword // weight: 0.1424
	$s8 = "SinglePropertyAccessor" fullword // weight: 0.1401
	$s9 = "XmlSerializerFormatAttribute" fullword // weight: 0.1321
	$s10 = "ReportIndications"  fullword // weight: 0.04565
	$s11 = "OriginatorPublicKey" fullword // weight: -0.07732
	$s12 = "MAEXPAVQChildEvent" fullword // weight: -0.1017
	$s13 = "FastObjectFactory"  fullword // weight: -0.1621
	$s14 = "31bf3856ad364e35"   fullword // weight: -0.2011

    condition:
	((#s0 * 0.569) + (#s1 * 0.427) + (#s2 * 0.142) + (#s3 * 0.142) + (#s4 * 0.142) + (#s5 * 0.142) + (#s6 * 0.142) + (#s7 * 0.142) + (#s8 * 0.140) + (#s9 * 0.132) + (#s10 * 0.046) + (#s11 * -0.077) + (#s12 * -0.102) + (#s13 * -0.162) + (#s14 * -0.201) + (-4.599)) > 0

}
