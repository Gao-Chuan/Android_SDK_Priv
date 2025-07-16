package org.example.check;

import org.example.util.PrivacyAPISummary;
import org.example.util.Utils;
import org.example.xq.Globals;
import org.json.JSONObject;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Value;
import soot.jimple.Constant;
import soot.jimple.DoubleConstant;
import soot.jimple.FloatConstant;
import soot.jimple.IntConstant;
import soot.jimple.InvokeExpr;
import soot.jimple.LongConstant;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;

import java.io.StringWriter;
import java.util.*;

public class HardCodeConfiguration {

	public class Result {
		private final boolean isHardCoded;
		private final Set<Object> constantsUsed;
		private final String priv_API_Signature;

		public Result(boolean isHardCoded, Set<Object> constantsUsed, String priv_API_Signature) {
			this.isHardCoded = isHardCoded;
			this.constantsUsed = constantsUsed;
			this.priv_API_Signature = priv_API_Signature;
		}

		public boolean isHardCoded() {
			return isHardCoded;
		}

		public Set<Object> getConstantsUsed() {
			return constantsUsed;
		}

		public String getPrivAPISignature() {
			return priv_API_Signature;
		}

		@Override
		public String toString() {
			return "Result{" + "isHardCoded=" + isHardCoded + ", constantsUsed=" + constantsUsed
					+ ", priv_API_Signature='" + priv_API_Signature + '\'' + '}';
		}
	}

	private Object getConstantValue(Constant constant) {
		if (constant instanceof DoubleConstant) {
			return Double.valueOf(((DoubleConstant) constant).value);
		} else if (constant instanceof FloatConstant) {
			return Float.valueOf(((FloatConstant) constant).value);
		} else if (constant instanceof IntConstant) {
			// soot treats "short, byte, boolean, char" as integer
			// pending manual confirmation.
			return Integer.valueOf(((IntConstant) constant).value);
		} else if (constant instanceof LongConstant) {
			return Long.valueOf(((LongConstant) constant).value);
		} else if (constant instanceof StringConstant) {
			return ((StringConstant) constant).value;
		} else {
			return null;
		}
	}

	public Map<SootMethod, Result> analyzeHardCodedArguments(CallGraph cg, SootMethod targetMethod, int argIndex,
			Set<Object> unsafeConstants) {
		Map<SootMethod, Set<Object>> callerToArgsMap = new HashMap<>();
		Map<SootMethod, Result> result = new HashMap<>();

		for (Iterator<Edge> it = cg.edgesInto(targetMethod); it.hasNext();) {
			Edge edge = it.next();
			Stmt stmt = (Stmt) edge.srcStmt();
			if (stmt.containsInvokeExpr()) {
				InvokeExpr invokeExpr = stmt.getInvokeExpr();
				Value arg = invokeExpr.getArg(argIndex);

				if (arg instanceof Constant) {
					Object argValue = this.getConstantValue((Constant) arg);
					SootMethod callingMethod = edge.src();
					callerToArgsMap.computeIfAbsent(callingMethod, k -> new HashSet<>()).add(argValue);
				} else {
					// put a placeholder that a privacy call without constant parameter is a safe invoke
					// why we need this? com.JKCreative.SoftwareUpdate app, <com.appodeal.ads.adapters.adcolony.AdcolonyNetwork: void updatePrivacy(com.appodeal.ads.RestrictedData,com.adcolony.sdk.AdColonyAppOptions,java.lang.String)> calls <com.adcolony.sdk.AdColonyAppOptions: com.adcolony.sdk.AdColonyAppOptions setPrivacyFrameworkRequired(java.lang.String,boolean)> multiple times,
					// some of them are hard-coded while the others are not. 
					SootMethod callingMethod = edge.src();
					callerToArgsMap.computeIfAbsent(callingMethod, k -> new HashSet<>()).add(new String("SafeCallPlaceHolder: " + arg.toString()));
				}
			}
		}

		for (Map.Entry<SootMethod, Set<Object>> entry : callerToArgsMap.entrySet()) {
			Set<Object> argValues = entry.getValue();
			boolean isHardCoded = !Collections.disjoint(argValues, unsafeConstants)
					&& unsafeConstants.containsAll(argValues);
			result.put(entry.getKey(), new Result(isHardCoded, argValues, targetMethod.getSignature()));

			/*
			Utils.LOGGER.info("-----------------------Debug HardCodeConfiguration-----------------------");
			Utils.LOGGER.info("Caller: " + entry.getKey().getSignature());
			Utils.LOGGER.info("Callee: " + methodSignature);
			Utils.LOGGER.info("Unsafe Values");
			for (Object unsafeConstant : unsafeConstants) {
				Utils.LOGGER.info("\t" + unsafeConstant);
			}
			Utils.LOGGER.info("Arg Values");
			for (Object argValue : argValues) {
				Utils.LOGGER.info("\t" + argValue);
			}
			Utils.LOGGER.info("");
			*/
		}

		return result;
	}

	public static void run_analyze(CallGraph cg) {
		HardCodeConfiguration configuration = new HardCodeConfiguration();

		for (Map.Entry<String, List<PrivacyAPISummary.APIDescriptor>> entry : PrivacyAPISummary.sdks.entrySet()) {
			String sdkName = entry.getKey();
			List<PrivacyAPISummary.APIDescriptor> apiDescriptors = entry.getValue();

			for (PrivacyAPISummary.APIDescriptor descriptor : apiDescriptors) {
				if (descriptor.apiClazzName == null || descriptor.apiMethodName == null) {
					continue;
				}
				
				SootClass sootClass;

				try {
					sootClass = Scene.v().getSootClass(descriptor.apiClazzName);
					if (sootClass == null) {
						System.err.println("Class not found: " + descriptor.apiClazzName);
						continue;
					}

					for (SootMethod sootMethod : sootClass.getMethods()) {
						if (!sootMethod.getName().equals(descriptor.apiMethodName)) {
							continue;
						}
						String methodSignature = sootMethod.getSignature();

						// Convert ppArgs map to a set of unsafe constants
						Set<Object> unsafeConstants = new HashSet<>();
						for (Object ppArg : descriptor.ppArgs.values()) {
							// why we need this? soot uses int to cover boolean, so we need to convert
							// unsafe boolean to integer, which aligns with PrivacyAPISummary
							if (ppArg instanceof Boolean) {
								Integer intPPArg = Integer.valueOf((Boolean) ppArg ? 1 : 0);
								unsafeConstants.add(intPPArg);
							} else {
								unsafeConstants.add(ppArg);
							}
						}

						// There will only be 1 index
						for (Integer argIndex : descriptor.ppArgs.keySet()) {
							if (argIndex >= sootMethod.getParameterCount()) {
								continue;
							}
							
							Map<SootMethod, HardCodeConfiguration.Result> analysisResult = configuration
									.analyzeHardCodedArguments(cg, sootMethod, argIndex, unsafeConstants);
							if (null == analysisResult) {
								continue;
							}

							// someapp have enable() -> setconsent(true), disable() -> setconsent(false) in
							// the same caller calss
							// example is app.elika.baby, which calls
							// firebaseAnalytics.setAnalyticsCollectionEnabled(true); in
							// com.getcapacitor.community.firebaseanalytics.FirebaseAnalytics.
							// enable(PluginCall pluginCall), and otherwise in disable(PluginCall
							// pluginCall)
							// therefore, we want to avoid any report as long as a class calls both safe and
							// unsafe privacy apis.
							Set<SootClass> classThatCallSafeAPI = new HashSet<SootClass>();
							analysisResult.forEach((method, result) -> {
								if (!result.isHardCoded) {
									classThatCallSafeAPI.add(method.getDeclaringClass());
								}
							});

							analysisResult.forEach((method, result) -> {
								if (result.isHardCoded() && !method.getSignature().contains("dummyMainClass")
										&& !classThatCallSafeAPI.contains(method.getDeclaringClass())) {
									JSONObject obj = new JSONObject();
									obj.put("FlawType", "HardCodeConfiguration");
									obj.put("SdkName", sdkName);
									obj.put("PrivAPIMethodSignature", methodSignature);
									obj.put("PrivAPIMethodCaller", method.getSignature());
									obj.put("Result", result.toString());
									obj.put("ApkPath", Globals.APK_PATH);
									obj.put("PackageName", Globals.PACKAGE_NAME);

									StringWriter out = new StringWriter();
									obj.write(out);
									Utils.LOGGER.info(out.toString());
								}
							});
						}
					}
				} catch (RuntimeException e) {
					System.err.println(e.getMessage());
					continue;
				}
			}
		}
	}
}
