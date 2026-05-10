private import cpp
import semmle.code.cpp.ir.dataflow.DataFlow
import semmle.code.cpp.ir.dataflow.TaintTracking
import MySources
import MySinks
import MySummaries

module MyCodeInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node src) {
    isGPTDetectedSource(src)
  }

  predicate isSink(DataFlow::Node sink) {
    isGPTDetectedSink(sink)
  }

  predicate isBarrier(DataFlow::Node node) {
    none()
  }

  predicate isAdditionalFlowStep(DataFlow::Node n1, DataFlow::Node n2) {
    isGPTDetectedStep(n1, n2)
  }

  predicate observeDiffInformedIncrementalMode() { any() }
}

module MyCodeInjectionFlow = TaintTracking::Global<MyCodeInjectionConfig>;
