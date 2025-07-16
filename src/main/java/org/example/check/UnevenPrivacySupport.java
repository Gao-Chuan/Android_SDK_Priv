package org.example.check;

import java.io.StringWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import org.example.util.PrivacyAPISummary;
import org.example.util.Utils;
import org.example.util.PrivacyAPISummary.APIDescriptor;
import org.example.xq.Globals;
import org.json.JSONObject;

import soot.jimple.toolkits.callgraph.CallGraph;

public class UnevenPrivacySupport {
	public void analyze(CallGraph cg) {
		if (PrivacyLandscape.sdkConnectionsCombined.size() < 1) {
			Utils.LOGGER.info("No SDK Connections Found!");
			return;
		}
		checkUnevenLawSupport(PrivacyLandscape.sdkConnectionsCombined);
	}

	private static void checkUnevenLawSupport(Map<String, Set<String>> sdkConnections) {
		Map<String, Set<String>> sdkSupportedLaws = new HashMap<String, Set<String>>();
		for (String sdkName : PrivacyAPISummary.sdks.keySet()) {
			List<APIDescriptor> apis = PrivacyAPISummary.sdks.get(sdkName);
			sdkSupportedLaws.put(sdkName, new HashSet<String>());
			for (APIDescriptor api : apis) {
				if (api.apiType != PrivacyAPISummary.API_TYPE_INIT) {
					sdkSupportedLaws.get(sdkName).add(api.apiType);
				}
			}
		}

		for (Entry<String, Set<String>> sdkConnectionEntry : sdkConnections.entrySet()) {
			String callerSdk = sdkConnectionEntry.getKey();
			for (String calleeSdk : sdkConnectionEntry.getValue()) {
				if (!sdkSupportedLaws.get(callerSdk).equals(sdkSupportedLaws.get(calleeSdk))) {
					JSONObject obj = new JSONObject();
					obj.put("FlawType", "UnevenPrivacySupport");
					obj.put("CallerSDK", callerSdk);
					obj.put("CallerSDKLaws", sdkSupportedLaws.get(callerSdk).toString());
					obj.put("CalleeSDK", calleeSdk);
					obj.put("CalleeSDKLaws", sdkSupportedLaws.get(calleeSdk).toString());
					obj.put("ApkPath", Globals.APK_PATH);
					obj.put("PackageName", Globals.PACKAGE_NAME);

					StringWriter out = new StringWriter();
					obj.write(out);
					Utils.LOGGER.info(out.toString());
				} else {
					Utils.LOGGER.info(String.format("Same Law Support: %s (%s) --- %s (%s)", callerSdk,
							sdkSupportedLaws.get(callerSdk).toString(), calleeSdk,
							sdkSupportedLaws.get(calleeSdk).toString()));
				}
			}
		}
	}

}
