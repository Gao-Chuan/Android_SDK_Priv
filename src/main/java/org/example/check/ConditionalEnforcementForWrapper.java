package org.example.check;

import java.io.StringWriter;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.Stack;

import org.example.util.Utils;
import org.example.xq.Globals;
import org.json.JSONArray;
import org.json.JSONObject;

import soot.Local;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.ValueBox;
import soot.jimple.IfStmt;
import soot.jimple.InvokeStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.ExceptionalBlockGraph;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.scalar.Pair;

public class ConditionalEnforcementForWrapper {
	private static Set<Unit> getRecursiveDefs(ReachingDefinition mrd, Unit u) {
		Set<Unit> defs = new HashSet<>();
		
		Set<Unit> visited = new HashSet<>();
		Stack<Unit> stack = new Stack<>();
		stack.push(u);
		
		while (!stack.isEmpty()) {
			Unit current = stack.pop();
			visited.add(current);
			
			List<ValueBox> useBoxes = current.getUseBoxes();
			for (ValueBox vb : useBoxes) {
				if (! (vb.getValue() instanceof Local)) {
					continue;
				}
				
				Local local = (Local) vb.getValue();
				for (Unit defUnit : mrd.getDefsOfAt(local, current)) {
					if (!visited.contains(defUnit)) {
						stack.push(defUnit);
					}
					defs.add(defUnit);
				}
			}
		}
		
		return defs;
	}

	private static boolean hasDataDependency(ReachingDefinition mrd, Block conditionBlock, Block callerBlock) {
		IfStmt ifStmt = null;
		for (Unit stmt : conditionBlock) {
			if (stmt instanceof IfStmt) {
				ifStmt = (IfStmt) stmt;
				break;
			}
		}

		Set<Unit> ifDefs = getRecursiveDefs(mrd, ifStmt);
		
		// this is based on the observation that if the if stmt comes from the method parameter, it is often an implicit data flow to the privacy API, rather than unrelated conditions. 
		// the impact of this check is not thoroughly evaluated either. 
		for (Unit ifDef : ifDefs) {
			if (ifDef.toString().contains(":= @parameter")) {
				return true;
			}
		}
		
		for (Unit u : callerBlock) {
			Set<Unit> uDefs = getRecursiveDefs(mrd, u);
			for (Unit uDef : uDefs) {
				if (ifDefs.contains(uDef)) {
					return true;
				}
			}
		}

		return false;
	}

	private static JSONArray blockToJSONArray(Block block) {
		JSONArray pathArray = new JSONArray();
		for (Unit stmt : block) {
			pathArray.put(stmt.toString());
		}
		return pathArray;
	}

	private static void addSuccessorsRecursively(Block block, Set<Block> successorsSet) {
		successorsSet.add(block);
		for (Block successor : block.getSuccs()) {
			if (!successorsSet.contains(successor)) {
				addSuccessorsRecursively(successor, successorsSet);
			}
		}
	}

	public static void reportSuspiciousConditions(String callerSdkName, String calleeSdkName, String apiType,
			List<SootMethod> path, Set<Pair<String, String>> expectedCalleeApis) {
		CallGraph cg = Scene.v().getCallGraph();

		Utils.LOGGER.info(String.format("Check conditions for (%s) %s -- %s", apiType, callerSdkName, calleeSdkName));

		for (int pathIndex = 0; pathIndex < path.size() - 1; ++pathIndex) {
			try {
				SootMethod currentMethod = path.get(pathIndex);
				SootMethod nextMethod = path.get(pathIndex + 1);

				if (!currentMethod.hasActiveBody()) {
					continue;
				}

				BlockGraph blockGraph = new ExceptionalBlockGraph(currentMethod.getActiveBody());
				Set<Block> callerBlocks = new HashSet<>();
				Set<Block> conditionBlocks = new HashSet<>();

				for (Block block : blockGraph) {
					for (Unit stmt : block) {
						if (stmt instanceof IfStmt) {
							conditionBlocks.add(block);
						}

						if (stmt instanceof InvokeStmt) {
							for (Iterator<Edge> it = cg.edgesOutOf(stmt); it.hasNext();) {
								SootMethod tgt = it.next().tgt();
								if (tgt.equals(nextMethod)) {
									callerBlocks.add(block);
								}
							}
						}
					}
				}

				Utils.LOGGER.info(String.format("# Caller Block %d, # Condition Block %d, in %s, looking for %s",
						callerBlocks.size(), conditionBlocks.size(), currentMethod.getSignature(),
						nextMethod.getSignature()));

				Set<Pair<Block, Block>> suspiciousBlockPair = new HashSet<>();

				// for each conditional block, we check if they lead to imbalanced privacy APIs.
				for (Block conditionBlock : conditionBlocks) {
					if (conditionBlock.getSuccs().size() < 2) {
						continue;
					}

					Set<Block> lSuccs = new HashSet<Block>();
					addSuccessorsRecursively(conditionBlock.getSuccs().get(0), lSuccs);

					Set<Block> rSuccs = new HashSet<Block>();
					addSuccessorsRecursively(conditionBlock.getSuccs().get(1), rSuccs);

					Utils.LOGGER.info(String.format("# lSucc %d, # rSucc %d", lSuccs.size(), rSuccs.size()));

					Set<Block> lSuccsWithCaller = new HashSet<>(lSuccs);
					lSuccsWithCaller.retainAll(callerBlocks);

					Set<Block> rSuccsWithCaller = new HashSet<>(rSuccs);
					rSuccsWithCaller.retainAll(callerBlocks);

					if (lSuccsWithCaller.size() > 0 && rSuccsWithCaller.size() <= 0) {
						for (Block lblock : lSuccsWithCaller) {
							suspiciousBlockPair.add(new Pair<>(conditionBlock, lblock));
						}
					}

					if (rSuccsWithCaller.size() > 0 && lSuccsWithCaller.size() <= 0) {
						for (Block rblock : rSuccsWithCaller) {
							suspiciousBlockPair.add(new Pair<>(conditionBlock, rblock));
						}
					}
				}

				if (suspiciousBlockPair.size() > 0) {
					ExceptionalUnitGraph eug = new ExceptionalUnitGraph(currentMethod.getActiveBody());
					ReachingDefinition rd = new ReachingDefinition(eug);

					for (Pair<Block, Block> blockPair : suspiciousBlockPair) {
						if (!hasDataDependency(rd, blockPair.getO1(), blockPair.getO2())) {
							JSONObject obj = new JSONObject();
							obj.put("FlawType", "ConditionalEnforcementForWrapper");
							obj.put("CallerSdkName", callerSdkName);
							obj.put("CalleeSdkName", calleeSdkName);
							obj.put("ApiType", apiType);
							JSONArray pathArray = new JSONArray();
							for (SootMethod pathElement : path) {
								pathArray.put(pathElement.getSignature());
							}
							obj.put("DelegationPath", pathArray);

							obj.put("CurrentMethod", currentMethod.getSignature());
							obj.put("ConditionBlock", blockToJSONArray(blockPair.getO1()));
							obj.put("BranchBlock", blockToJSONArray(blockPair.getO2()));

							obj.put("ApkPath", Globals.APK_PATH);
							obj.put("PackageName", Globals.PACKAGE_NAME);

							StringWriter out = new StringWriter();
							obj.write(out);
							Utils.LOGGER.info(out.toString());
						} else {
							Utils.LOGGER.info(String.format("Has data dependency in %s...", currentMethod.getSignature()));
							JSONObject obj = new JSONObject();
							obj.put("CurrentMethod", currentMethod.getSignature());
							obj.put("ConditionBlock", blockToJSONArray(blockPair.getO1()));
							obj.put("BranchBlock", blockToJSONArray(blockPair.getO2()));
							StringWriter out = new StringWriter();
							obj.write(out);
							Utils.LOGGER.info(out.toString());
						}
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}