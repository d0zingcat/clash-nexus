package egern

import "strings"

// Split only commas outside parentheses. Reject unbalanced expressions rather
// than emitting a weakened rule when any logical operand cannot be converted.
func egernRuleFields(rule string) []string {
	var fields []string
	depth, start := 0, 0
	for i, ch := range rule {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
			if depth < 0 {
				return nil
			}
		case ',':
			if depth == 0 {
				fields = append(fields, strings.TrimSpace(rule[start:i]))
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil
	}
	return append(fields, strings.TrimSpace(rule[start:]))
}

func convertEgernLogicalRule(rule string, withPolicy bool, providers map[string]string) map[string]interface{} {
	fields := egernRuleFields(rule)
	want := 2
	if withPolicy {
		want = 3
	}
	if len(fields) != want || len(fields[1]) < 2 {
		return nil
	}
	kind := strings.ToLower(fields[0])
	if kind != "and" && kind != "or" && kind != "not" {
		return nil
	}
	expression := fields[1]
	if expression[0] != '(' || expression[len(expression)-1] != ')' {
		return nil
	}
	operands := egernRuleFields(expression[1 : len(expression)-1])
	if len(operands) == 0 || (kind == "not" && len(operands) != 1) {
		return nil
	}
	children := []map[string]interface{}{}
	for _, operand := range operands {
		if len(operand) < 2 || operand[0] != '(' || operand[len(operand)-1] != ')' {
			return nil
		}
		operand = operand[1 : len(operand)-1]
		parts := egernRuleFields(operand)
		if len(parts) < 2 {
			return nil
		}
		childType := strings.ToUpper(parts[0])
		var child map[string]interface{}
		if childType == "AND" || childType == "OR" || childType == "NOT" {
			child = convertEgernLogicalRule(operand, false, providers)
		} else {
			noResolve := len(parts) == 3 && strings.EqualFold(parts[2], "no-resolve")
			if len(parts) != 2 && !noResolve || childType == "MATCH" || childType == "FINAL" {
				return nil
			}
			child = convertRuleToEgern(childType, parts[1], "", noResolve, providers)
			for _, raw := range child {
				delete(raw.(map[string]interface{}), "policy")
			}
		}
		if child == nil {
			return nil
		}
		children = append(children, child)
	}
	out := map[string]interface{}{"match": children}
	if kind == "not" {
		out["match"] = children[0]
	}
	if withPolicy {
		if fields[2] == "" {
			return nil
		}
		out["policy"] = fields[2]
	}
	return map[string]interface{}{kind: out}
}
