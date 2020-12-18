rule solarwinds_detector4
{
    strings:
        $s0 = "GetSubKeyAndValueNames" fullword // weight: 1.044
        $s1 = "IsNullOrInvalidName" fullword // weight: 1.044
        $s2 = "RegistrySecurity"   fullword // weight: 1.023
        $s3 = "GetSystemWebProxy"  fullword // weight: 0.9661
        $s4 = "GetCurrentString"   fullword // weight: 0.8466
        $s5 = "OnReflowAllNodeChildStatus" fullword // weight: 0.719
        $s6 = "EnumerateExecutionEngines" fullword // weight: 0.6766
        $s7 = "RemoveExecutionEngine" fullword // weight: 0.6766
        $s8 = "SelectionPriority"  fullword // weight: 0.5645
        $s9 = "ProcessPluginsWithInterface" fullword // weight: 0.4341
        $s10 = "MaxThresholdPollsInterval" fullword // weight: 0.3298
        $s11 = "GetNewAlertsSwql"   fullword // weight: 0.3037
        $s12 = "OneTimeJobRawResult" fullword // weight: 0.3037
        $s13 = "SourceInstanceProperties" fullword // weight: 0.2818
        $s14 = "UnacknowledgeAlertsAction" fullword // weight: 0.2171
        $s15 = "discoveryPlugins"   fullword // weight: 0.2171
        $s16 = "ScheduleMaintananceExpiration" fullword // weight: 0.2171
        $s17 = "IsWorkItemCanceled" fullword // weight: 0.2148
        $s18 = "CacheConfiguration" fullword // weight: 0.1969
        $s19 = "GetAlertUpdatedNotificationPropertiesByAlertObjectIds" fullword // weight: 0.1756
        $s20 = "SetProcessPrivilege" fullword // weight: 0.126
        $s21 = "AlertNotification"  fullword // weight: 0.07279
        $s22 = "subscriptionProvider" fullword // weight: 0.01047
        $s23 = "IEventSystemHandler" fullword // weight: -0.0847
        $s24 = "ApplyPollingIntervals" fullword // weight: -0.08617
        $s25 = "RemoveAdvancedAlerts" fullword // weight: -0.08617
        $s26 = "IsBasicOrFullOrion" fullword // weight: -0.1193
        $s27 = "InformationServiceSubscriptionProviderBase" fullword // weight: -0.1277
        $s28 = "TransparentIdentifier0" fullword // weight: -0.1353
        $s29 = "moduleLicenseVersion" fullword // weight: -0.1516
        $s30 = "QueryAutoDependenciesForParentNode" fullword // weight: -0.1783
        $s31 = "ConfigureJobEngineV2" fullword // weight: -0.1806
        $s32 = "SecurityProtocolType" fullword // weight: -0.2134
        $s33 = "CreateSystemConnectionToMainHostV3" fullword // weight: -0.2426
        $s34 = "X509Certificates"   fullword // weight: -0.3158
        $s35 = "ISolarWindsAssemblyResolver" fullword // weight: -0.3249
        $s36 = "ResyncToParticipationRules" fullword // weight: -1.004

    condition:
        ((#s0 * 1.044) + (#s1 * 1.044) + (#s2 * 1.023) + (#s3 * 0.966) + (#s4 * 0.847) + (#s5 * 0.719) + (#s6 * 0.677) + (#s7 * 0.677) + (#s8 * 0.565) + (#s9 * 0.434) + (#s10 * 0.330) + (#s11 * 0.304) + (#s12 * 0.304) + (#s13 * 0.282) + (#s14 * 0.217) + (#s15 * 0.217) + (#s16 * 0.217) + (#s17 * 0.215) + (#s18 * 0.197) + (#s19 * 0.176) + (#s20 * 0.126) + (#s21 * 0.073) + (#s22 * 0.010) + (#s23 * -0.085) + (#s24 * -0.086) + (#s25 * -0.086) + (#s26 * -0.119) + (#s27 * -0.128) + (#s28 * -0.135) + (#s29 * -0.152) + (#s30 * -0.178) + (#s31 * -0.181) + (#s32 * -0.213) + (#s33 * -0.243) + (#s34 * -0.316) + (#s35 * -0.325) + (#s36 * -1.004) + (-9.282)) > -1.5

}
