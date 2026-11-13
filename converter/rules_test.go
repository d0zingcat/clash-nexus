package converter

import (
	"reflect"
	"testing"
)

func TestRejectRemovedProxyRules(t *testing.T) {
	rules := []interface{}{
		"DOMAIN-SUFFIX,ts.net,Lost",
		"IP-CIDR,100.64.0.0/10, Lost ,no-resolve",
		"AND,((DOMAIN,a),(OR,((NETWORK,tcp),(DST-PORT,443)))),Lost",
		"RULE-SET,remote,Lost,no-resolve",
		"MATCH,Lost",
		"FINAL,Lost",
		"DOMAIN,valid,Kept",
		"DOMAIN,remote,ProviderNode",
		"DOMAIN,group,Group",
		nil,
	}
	want := append([]interface{}(nil), rules...)
	want[0] = "DOMAIN-SUFFIX,ts.net,REJECT"
	want[1] = "IP-CIDR,100.64.0.0/10,REJECT,no-resolve"
	want[2] = "AND,((DOMAIN,a),(OR,((NETWORK,tcp),(DST-PORT,443)))),REJECT"
	want[3] = "RULE-SET,remote,REJECT,no-resolve"
	want[4] = "MATCH,REJECT"
	want[5] = "FINAL,REJECT"
	before := append([]interface{}(nil), rules...)
	var warnings []string
	got := RejectRemovedProxyRules(rules,
		[]map[string]interface{}{{"name": "Lost"}, {"name": "Kept"}, {"name": "Group"}},
		[]map[string]interface{}{{"name": "Group"}}, map[string]bool{"Kept": true}, "test", &warnings)
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(rules, before) || len(warnings) != 6 {
		t.Fatalf("got %#v, warnings %v; input %#v", got, warnings, rules)
	}
}
