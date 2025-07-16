package org.example.xq;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

import soot.Local;
import soot.SootField;
import soot.SootMethod;
import soot.Type;
import soot.Value;
import soot.ValueBox;
import soot.VoidType;
import soot.jimple.DefinitionStmt;
import soot.jimple.FieldRef;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.StringConstant;
import soot.jimple.infoflow.InfoflowManager;
import soot.jimple.infoflow.android.InfoflowAndroidConfiguration;
import soot.jimple.infoflow.android.callbacks.AndroidCallbackDefinition;
import soot.jimple.infoflow.android.resources.controls.AndroidLayoutControl;
import soot.jimple.infoflow.android.source.AccessPathBasedSourceSinkManager;
import soot.jimple.infoflow.data.AccessPath;
import soot.jimple.infoflow.data.AccessPath.ArrayTaintType;
import soot.jimple.infoflow.entryPointCreators.SimulatedCodeElementTag;
import soot.jimple.infoflow.sourcesSinks.definitions.AccessPathTuple;
import soot.jimple.infoflow.sourcesSinks.definitions.FieldSourceSinkDefinition;
import soot.jimple.infoflow.sourcesSinks.definitions.ISourceSinkDefinition;
import soot.jimple.infoflow.sourcesSinks.definitions.StatementSourceSinkDefinition;
import soot.jimple.infoflow.sourcesSinks.manager.SinkInfo;
import soot.jimple.infoflow.sourcesSinks.manager.SourceInfo;
import soot.toolkits.scalar.Pair;

public class MyAccessPathBasedSourceSinkManager extends AccessPathBasedSourceSinkManager {
	private Set<String> stringSourceSigs;
	private Set<String> fieldSourceSigs;
	private Map<Pair<String, String>, Set<String>> stmtSourceSigs;

	public MyAccessPathBasedSourceSinkManager(Collection<? extends ISourceSinkDefinition> sources, Collection<? extends ISourceSinkDefinition> sinks,
			Set<AndroidCallbackDefinition> callbackMethods,
			InfoflowAndroidConfiguration config,
			Map<Integer, AndroidLayoutControl> layoutControls, Set<String> stringSourceSigs,
			Set<String> fieldSourceSigs, Map<Pair<String, String>, Set<String>> stmtSourceSigs) {
		super(sources, sinks, callbackMethods, config, layoutControls);

		this.stringSourceSigs = stringSourceSigs;
		this.fieldSourceSigs = fieldSourceSigs;
		this.stmtSourceSigs = stmtSourceSigs;
	}

	private boolean isStmtSource(Stmt sCallSite, InfoflowManager manager) {
		SootMethod method = manager.getICFG().getMethodOf(sCallSite);
		Pair<String, String> methodKey = new Pair<String, String>(method.getDeclaringClass().getName(), method.getSubSignature());
		
		if (this.stmtSourceSigs.containsKey(methodKey)) {
			for (String stmtSig : this.stmtSourceSigs.get(methodKey)) {
				if (sCallSite.toString().contains(stmtSig)) {
					return true;
				}
			}
		}
		
		return false;
	}

	private boolean isStringSource(Stmt sCallSite) {
		List<ValueBox> checkConstUseBoxes = sCallSite.getUseBoxes();
		for (ValueBox ccVB : checkConstUseBoxes) {
			if (ccVB.getValue() instanceof StringConstant) {
				String strV = ((StringConstant) ccVB.getValue()).value;

				for (String strSourceSig : this.stringSourceSigs) {
					if (Pattern.matches(strSourceSig, strV)) {
						return true;
					}
				}
			}
		}
		return false;
	}

	private boolean isFieldSource(Stmt sCallSite) {
		try {
			if (sCallSite instanceof DefinitionStmt) {
				Value rhs = ((DefinitionStmt) sCallSite).getRightOp();
				if (rhs instanceof FieldRef) {
					SootField rhsField = ((FieldRef) rhs).getField();
					if (this.fieldSourceSigs.contains(rhsField.getSignature())) {
						return true;
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return false;
	}

	public boolean isAdditionalSource(Stmt sCallSite, InfoflowManager manager) {
		return (this.isStringSource(sCallSite) || this.isStmtSource(sCallSite, manager) || this.isFieldSource(sCallSite));
	}

	@Override
	public SourceInfo getSourceInfo(Stmt sCallSite, InfoflowManager manager) {
		SourceInfo ret = super.getSourceInfo(sCallSite, manager);
		
		SootMethod method = manager.getICFG().getMethodOf(sCallSite);
		
		if (!isAdditionalSource(sCallSite, manager)) {
			return ret;
		}

		System.out.println("additional source " + sCallSite.toString() + " at " + method.getSignature());
		
		try {
			if (sCallSite instanceof DefinitionStmt) {
				Value lhs = ((DefinitionStmt) sCallSite).getLeftOp();
				if (lhs instanceof FieldRef) {
					SootField lhsField = ((FieldRef) lhs).getField();
					
					HashSet<ISourceSinkDefinition> defs = new HashSet<>();
					ISourceSinkDefinition def = new FieldSourceSinkDefinition(lhsField.getSignature());
					defs.add(def);
					this.sourceFields.put(lhsField, def);
					SourceInfo fret = new SourceInfo(createSourceInfoPairs(sCallSite, manager, defs));
					return fret;
				} else {
					Local local = null;
					for (ValueBox vb : sCallSite.getUseAndDefBoxes()) {
						if (vb.getValue() instanceof Local) {
							local = (Local) vb.getValue();
							break;
						}
					}

					if (local != null) {
						Set<AccessPathTuple> apTuple = new HashSet<AccessPathTuple>();
						apTuple.add(AccessPathTuple.create(true, false));
						ISourceSinkDefinition def = new StatementSourceSinkDefinition(sCallSite, local, apTuple);
						HashSet<ISourceSinkDefinition> defs = new HashSet<>();
						defs.add(def);
						this.sourceStatements.put(sCallSite, def);

						SourceInfo fret = new SourceInfo(createSourceInfoPairs(sCallSite, manager, defs));
						return fret;
					}
				}
			} else if (sCallSite.containsInvokeExpr()) {
				if (sCallSite.getInvokeExpr() instanceof InstanceInvokeExpr) {
					Local lLocal = (Local) (((InstanceInvokeExpr) sCallSite.getInvokeExpr()).getBase());
					Set<AccessPathTuple> apTuple = new HashSet<AccessPathTuple>();
					apTuple.add(AccessPathTuple.create(true, false));
					ISourceSinkDefinition def = new StatementSourceSinkDefinition(sCallSite, lLocal, apTuple);
					HashSet<ISourceSinkDefinition> defs = new HashSet<>();
					defs.add(def);
					this.sourceStatements.put(sCallSite, def);

					SourceInfo fret = new SourceInfo(createSourceInfoPairs(sCallSite, manager, defs));
					return fret;
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	@Override
	public SinkInfo getSinkInfo(Stmt sCallSite, InfoflowManager manager, AccessPath sourceAccessPath) {
		return super.getSinkInfo(sCallSite, manager, sourceAccessPath);
	}
}
