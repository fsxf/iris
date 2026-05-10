/**
 * @name Use of a potentially dangerous function
 * @description Certain Python built-in routines are dangerous to call.
 * @kind problem
 * @problem.severity warning
 * @security-severity 10.0
 * @precision medium
 * @id python/potentially-dangerous-function
 * @tags security
 *       external/cwe/cwe-676
 */

import python
private import semmle.python.ApiGraphs

predicate safeYamlLoader(API::CallNode call) {
  exists(Expr loader |
    call.getArgByName("Loader").asExpr() = loader and
    loader.toString().matches("%SafeLoader%")
  )
}

predicate shellTrue(API::CallNode call) {
  exists(Expr shell |
    call.getArgByName("shell").asExpr() = shell and
    shell instanceof BooleanLiteral and
    shell.toString() = "True"
  )
}

predicate dangerousCall(API::CallNode call, string message) {
  exists(string name |
    name = ["eval", "exec", "compile"] and
    call = API::builtin(name).getACall() and
    message = "Call to Python built-in '" + name + "' can execute dynamically constructed code."
  )
  or
  exists(string mod, string name |
    mod = ["pickle", "cPickle", "dill", "marshal"] and
    name = ["load", "loads"] and
    call = API::moduleImport(mod).getMember(name).getACall() and
    message = "Call to '" + mod + "." + name + "' can deserialize attacker-controlled data."
  )
  or
  call = API::moduleImport("yaml").getMember("load").getACall() and
  not safeYamlLoader(call) and
  message = "Call to 'yaml.load' without SafeLoader can construct arbitrary Python objects."
  or
  exists(string name |
    name = ["system", "popen"] and
    call = API::moduleImport("os").getMember(name).getACall() and
    message = "Call to 'os." + name + "' can execute shell commands."
  )
  or
  exists(string name |
    name = ["call", "check_call", "check_output", "run", "Popen"] and
    call = API::moduleImport("subprocess").getMember(name).getACall() and
    shellTrue(call) and
    message = "Call to 'subprocess." + name + "' with shell=True can execute shell commands."
  )
  or
  exists(string name |
    name = ["getoutput", "getstatusoutput"] and
    call = API::moduleImport("commands").getMember(name).getACall() and
    message = "Call to 'commands." + name + "' executes shell commands."
  )
}

from API::CallNode call, string message
where dangerousCall(call, message)
select call.asExpr(), message
