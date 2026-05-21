package observability

import (
	"expvar"
	"math"
	"strconv"
	"strings"
)

type ExpvarSample struct {
	Name   string
	Labels []ExpvarLabel
	Int64  *int64
	Float  *float64
}

type ExpvarLabel struct {
	Name  string
	Value string
}

func CollectAerolVMExpvars() []ExpvarSample {
	var samples []ExpvarSample
	expvar.Do(func(kv expvar.KeyValue) {
		if !strings.HasPrefix(kv.Key, "aerolvm_") {
			return
		}
		collectExpvarSamples(kv.Key, kv.Value, nil, &samples)
	})
	return samples
}

func collectExpvarSamples(name string, v expvar.Var, labels []ExpvarLabel, samples *[]ExpvarSample) {
	if m, ok := v.(*expvar.Map); ok {
		depth := len(labels)
		labelName := "key"
		if depth > 0 {
			labelName = "key" + strconv.Itoa(depth+1)
		}
		m.Do(func(kv expvar.KeyValue) {
			childLabels := append(append([]ExpvarLabel(nil), labels...), ExpvarLabel{Name: labelName, Value: kv.Key})
			collectExpvarSamples(name, kv.Value, childLabels, samples)
		})
		return
	}
	if sample, ok := sampleFromExpvar(name, labels, v); ok {
		*samples = append(*samples, sample)
	}
}

func sampleFromExpvar(name string, labels []ExpvarLabel, v expvar.Var) (ExpvarSample, bool) {
	switch typed := v.(type) {
	case *expvar.Int:
		value := typed.Value()
		return ExpvarSample{Name: name, Labels: append([]ExpvarLabel(nil), labels...), Int64: &value}, true
	case *expvar.Float:
		value := typed.Value()
		if math.IsNaN(value) || math.IsInf(value, 0) {
			return ExpvarSample{}, false
		}
		return ExpvarSample{Name: name, Labels: append([]ExpvarLabel(nil), labels...), Float: &value}, true
	default:
		raw := strings.TrimSpace(v.String())
		if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return ExpvarSample{Name: name, Labels: append([]ExpvarLabel(nil), labels...), Int64: &i}, true
		}
		if f, err := strconv.ParseFloat(raw, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return ExpvarSample{Name: name, Labels: append([]ExpvarLabel(nil), labels...), Float: &f}, true
		}
		return ExpvarSample{}, false
	}
}
