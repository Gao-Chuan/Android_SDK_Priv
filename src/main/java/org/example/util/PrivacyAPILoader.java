package org.example.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.util.*;

public class PrivacyAPILoader {

	public static void loadPrivacyAPIs(String jsonFilePath) {
		ObjectMapper mapper = new ObjectMapper();
		try {
			JsonNode rootNode = mapper.readTree(new File(jsonFilePath));
			Iterator<Map.Entry<String, JsonNode>> fields = rootNode.fields();

			while (fields.hasNext()) {
				Map.Entry<String, JsonNode> entry = fields.next();
				String sdkName = entry.getKey();
				JsonNode sdkNode = entry.getValue();

				if ("Startapp" == sdkName || "HyprMX" == sdkName) {
					continue;
				}

				List<PrivacyAPISummary.APIDescriptor> apis = new ArrayList<>();

				try {
					sdkNode.fields().forEachRemaining(e -> {
						try {
							String apiType = mapApiType(e.getKey());
							JsonNode apiArrayNode = e.getValue();

							if (apiArrayNode.isTextual() && apiArrayNode.asText().equalsIgnoreCase("No API Found")) {
//                                System.out.println("No API found for type " + apiType + " in SDK " + sdkName);
							} else if (apiArrayNode.isArray()) {
								apiArrayNode.forEach(apiNode -> {
									if (apiNode.isTextual() && apiNode.asText().equals("IAB Framework")) {
										apis.add(new PrivacyAPISummary.APIDescriptor(apiType, null, null, null, null,
												true));
									} else if (apiNode.isObject()) {
										String apiClazzName = apiNode.get("apiClazzName").asText();
										String apiMethodName = apiNode.get("apiMethodName").asText();

										// jimple uses <init> as method name for instance constructors.
										if (apiMethodName.equals("$init")) {
											apiMethodName = "<init>";
										}

										if (!apiClazzName.equals("java.util.HashMap")) {
											Map<Integer, Object> qualifierArgs = getQualifierArgs(
													apiNode.get("policyArgs"));
											Map<Integer, Object> ppArgs = getPPArgs(apiNode.get("consentArgsIndex"),
													apiNode.get("consentArgsValue"));

											// if (ppArgs != null) { // Only add the APIDescriptor if ppArgs is not null
											// xw: doing my best guess: we might need to remove this condition since
											// "init" is excluded by this condition
											PrivacyAPISummary.APIDescriptor descriptor = new PrivacyAPISummary.APIDescriptor(
													apiType, apiClazzName, apiMethodName, qualifierArgs, ppArgs, false);
//                                            System.out.println(descriptor.toString()); // Logging the APIDescriptor details to console
											apis.add(descriptor);
											// }
										}
									} else {
										System.err.println(
												"Unexpected format for type " + apiType + " in SDK " + sdkName);
									}
								});
							} else {
								System.err.println("Unexpected format for type " + apiType + " in SDK " + sdkName);
							}
						} catch (Exception ex) {
							System.err.println("ERROR:>>" + sdkName);
							ex.printStackTrace();
						}
					});
				} catch (Exception ex) {
					System.err.println("ERROR processing SDK: " + sdkName);
					ex.printStackTrace();
				}

				PrivacyAPISummary.sdks.put(sdkName, apis);
			}

		} catch (IOException e) {
			e.printStackTrace();
		}

		if (PrivacyAPISummary.sdks.containsKey("adMost")) {
			PrivacyAPISummary.APIDescriptor descriptor = new PrivacyAPISummary.APIDescriptor(
					PrivacyAPISummary.API_TYPE_INIT, "admost.sdk.base.AdMost", "init", null, null, false);
			PrivacyAPISummary.sdks.get("adMost").add(descriptor);
		}

		if (PrivacyAPISummary.sdks.containsKey("Ironsource")) {
			PrivacyAPISummary.APIDescriptor descriptor = new PrivacyAPISummary.APIDescriptor(
					PrivacyAPISummary.API_TYPE_INIT, "com.ironsource.mediationsdk.IronSource", "initISDemandOnly", null,
					null, false);
			PrivacyAPISummary.sdks.get("Ironsource").add(descriptor);
		}
	}

	private static Map<Integer, Object> getQualifierArgs(JsonNode policyArgsNode) {
		if (policyArgsNode != null && policyArgsNode.isObject()) {
			Map<Integer, Object> qualifierArgs = new HashMap<>();
			policyArgsNode.fields().forEachRemaining(entry -> {
				try {
					Integer index = Integer.parseInt(entry.getKey());
					qualifierArgs.put(index, entry.getValue().asText());
				} catch (NumberFormatException e) {
					e.printStackTrace();
				}
			});
			return qualifierArgs;
		}
		return null;
	}

	private static String mapApiType(String jsonApiType) {
		// Adjust the mapping as per your requirements
		switch (jsonApiType.toLowerCase()) {
		case "init":
			return PrivacyAPISummary.API_TYPE_INIT;
		case "gdpr":
			return PrivacyAPISummary.API_TYPE_GDPR;
		case "us_p":
			return PrivacyAPISummary.API_TYPE_CCPA;
		case "coppa":
			return PrivacyAPISummary.API_TYPE_COPPA;
		default:
			throw new IllegalArgumentException("Unsupported API Type: " + jsonApiType);
		}
	}

	private static Map<Integer, Object> getPPArgs(JsonNode consentArgsIndexNode, JsonNode consentArgsValueNode) {
		Map<Integer, Object> ppArgs = new HashMap<>();

		if (consentArgsIndexNode != null && consentArgsValueNode != null && consentArgsValueNode.isObject()) {
			Integer index = consentArgsIndexNode.asInt();
			boolean keyFound = false;

			Iterator<Map.Entry<String, JsonNode>> iterator = consentArgsValueNode.fields();
			while (iterator.hasNext()) {
				Map.Entry<String, JsonNode> entry = iterator.next();
				String key = entry.getKey();
				JsonNode valueNode = entry.getValue();

				if (key.equals("gdpr_true") || key.equals("usp_false") || key.equals("coppa_false")) {
					if (valueNode.isBoolean()) {
						ppArgs.put(index, valueNode.asBoolean());
						keyFound = true;
					} else if (valueNode.isTextual()) { // && valueNode.asText().equals("call the api")
						ppArgs.put(index, valueNode.asText()); // Only store "call the api" for specified keys
						keyFound = true;
					} else if (valueNode.isInt()) {
						ppArgs.put(index, valueNode.asInt()); // Store integer values
						keyFound = true;
					}
//                    println(String.valueOf(consentArgsValueNode));
				}
			}
			return keyFound ? ppArgs : null;
		}
		return ppArgs.isEmpty() ? null : ppArgs; // Return null if ppArgs is empty
	}

}
