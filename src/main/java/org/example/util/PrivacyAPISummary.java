package org.example.util;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class PrivacyAPISummary {
    public static String API_TYPE_INIT = "INIT";
    public static String API_TYPE_GDPR = "GDPR";
    public static String API_TYPE_CCPA = "CCPA";
    public static String API_TYPE_COPPA = "COPPA";

    public static class APIDescriptor {
        public String apiType; // "INIT", "GDPR", "CCPA", "COPPA", etc.
        public boolean use_IAB;
        public String apiClazzName;
        public String apiMethodName;
        public Map<Integer, Object> qualifierArgs; // qualifier parameters when an API for multiple laws
        public Map<Integer, Object> ppArgs; // privacy-preserving parameter value (e.g., false for setHasUserConsent)

        public APIDescriptor(String apiType, String apiClazzName, String apiMethodName, Map<Integer, Object> qualifierArgs, Map<Integer, Object> ppArgs, boolean use_IAB) {
            this.apiType = apiType;
            this.apiClazzName = apiClazzName;
            this.apiMethodName = apiMethodName;
            this.qualifierArgs = qualifierArgs;
            this.ppArgs = ppArgs;
            this.use_IAB = use_IAB;
        }

        public String toString() {
            return "APIDescriptor{" +
                    "apiType='" + apiType + '\'' +
                    ", use_IAB=" + use_IAB +
                    ", apiClazzName='" + apiClazzName + '\'' +
                    ", apiMethodName='" + apiMethodName + '\'' +
                    ", qualifierArgs=" + qualifierArgs +
                    ", ppArgs=" + ppArgs +
                    '}';
        }
    }

    public static Map<String, List<APIDescriptor>> sdks = new HashMap<String, List<APIDescriptor>>();

    public static void initTestCases() {
        sdks = new HashMap<String, List<APIDescriptor>>();

        String sdkName = null;
        List<APIDescriptor> apis = null;
        sdkName = "AppLovin";
        apis = new ArrayList<APIDescriptor>();
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_INIT,
                "com.applovin.sdk.AppLovinSdk",
                "initializeSdk",
                null,
                null,
                false));
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_GDPR,
                "com.applovin.sdk.AppLovinPrivacySettings",
                "setHasUserConsent",
                null,
                new HashMap<Integer, Object>() {{
                    put(0, true);
                }},
                false));
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_CCPA,
                "com.applovin.sdk.AppLovinPrivacySettings",
                "setDoNotSell",
                null,
                new HashMap<Integer, Object>() {{
                    put(0, false);
                }},
                false));
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_COPPA,
                "com.applovin.sdk.AppLovinPrivacySettings",
                "setIsAgeRestrictedUser",
                null,
                new HashMap<Integer, Object>() {{
                    put(0, false);
                }},
                false));
        sdks.put(sdkName, apis);


        sdkName = null;
        apis = null;

        sdkName = "Bytedance";
        apis = new ArrayList<APIDescriptor>();
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_INIT,
                "com.bytedance.sdk.openadsdk.api.init.PAGSdk",
                "init",
                null,
                null,
                false));
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_GDPR,
                "com.bytedance.sdk.openadsdk.api.init.PAGConfig$Builder",
                "setGDPRConsent",
                null,
                new HashMap<Integer, Object>() {{
                    put(0, 1);
                }},
                false));
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_CCPA,
                "com.bytedance.sdk.openadsdk.api.init.PAGConfig$Builder",
                "setDoNotSell",
                null,
                new HashMap<Integer, Object>() {{
                    put(0, 0);
                }},
                false));
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_COPPA,
                "com.bytedance.sdk.openadsdk.api.init.PAGConfig$Builder",
                "setChildDirected",
                null,
                new HashMap<Integer, Object>() {{
                    put(0, 0);
                }},
                false));
        sdks.put(sdkName, apis);

        sdkName = null;
        apis = null;

        sdkName = "Ironsource";
        apis = new ArrayList<APIDescriptor>();
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_INIT,
                "com.ironsource.sdk.IronSourceNetwork",
                "initSDK",
                null,
                null,
                false));
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_GDPR,
                "com.ironsource.mediationsdk.IronSource",
                "setConsent",
                null,
                new HashMap<Integer, Object>() {{
                    put(0, 1);
                }},
                false));
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_CCPA,
                "com.ironsource.mediationsdk.IronSource",
                "setMetaData",
                new HashMap<Integer, Object>() {{
                    put(0, "do_not_sell");
                }},
                new HashMap<Integer, Object>() {{
                    put(1, 0);
                }},
                false));
        apis.add(new APIDescriptor(PrivacyAPISummary.API_TYPE_COPPA,
                "com.ironsource.mediationsdk.IronSource",
                "setMetaData",
               new HashMap<Integer, Object>() {{
                   put(0, "is_child_directed");
               }},
                new HashMap<Integer, Object>() {{
                    put(1, true);
                }},
                false));
        sdks.put(sdkName, apis);
    }
}
