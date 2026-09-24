package hako

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"
)

func YamlToJSON(rawYAML string) (*StringBox, error) {
	if err := validateConfigurationInput(rawYAML); err != nil {
		return nil, bridgeSafeError(err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(rawYAML))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: decode YAML: %w", err))
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, bridgeSafeError(fmt.Errorf("hako: YAML configuration root must be an object"))
	}

	var safety any
	if err := document.Content[0].Decode(&safety); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: reject unsafe YAML configuration: %w", err))
	}

	var payload bytes.Buffer
	if err := encodeYAMLNodeAsJSON(document.Content[0], &payload); err != nil {
		return nil, bridgeSafeError(err)
	}
	if err := validateConfigurationJSONResult(payload.String()); err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(payload.String()), nil
}

func encodeYAMLNodeAsJSON(node *yaml.Node, buf *bytes.Buffer) error {
	switch node.Kind {
	case yaml.AliasNode:
		return encodeYAMLNodeAsJSON(node.Alias, buf)
	case yaml.MappingNode:
		pairs, err := resolvedMappingPairs(node)
		if err != nil {
			return err
		}
		buf.WriteByte('{')
		for index, pair := range pairs {
			if index > 0 {
				buf.WriteByte(',')
			}
			key, err := json.Marshal(pair.key)
			if err != nil {
				return err
			}
			buf.Write(key)
			buf.WriteByte(':')
			if err := encodeYAMLNodeAsJSON(pair.value, buf); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
		return nil
	case yaml.SequenceNode:
		buf.WriteByte('[')
		for index, item := range node.Content {
			if index > 0 {
				buf.WriteByte(',')
			}
			if err := encodeYAMLNodeAsJSON(item, buf); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
		return nil
	default:
		var value any
		if err := node.Decode(&value); err != nil {
			return fmt.Errorf("hako: decode YAML scalar: %w", err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("hako: encode YAML scalar as JSON: %w", err)
		}
		buf.Write(encoded)
		return nil
	}
}

type yamlMappingPair struct {
	key   string
	value *yaml.Node
}

func resolvedMappingPairs(node *yaml.Node) ([]yamlMappingPair, error) {
	explicit := make(map[string]bool)
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		if isMergeKey(key) {
			continue
		}
		keyString, err := mappingKeyString(key)
		if err != nil {
			return nil, err
		}
		if explicit[keyString] {
			return nil, fmt.Errorf("hako: duplicate YAML mapping key %q", keyString)
		}
		explicit[keyString] = true
	}
	seen := make(map[string]bool)
	pairs := make([]yamlMappingPair, 0, len(node.Content)/2)
	appendPair := func(key string, value *yaml.Node) {
		if seen[key] {
			return
		}
		seen[key] = true
		pairs = append(pairs, yamlMappingPair{key: key, value: value})
	}
	for index := 0; index+1 < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		if isMergeKey(key) {
			sources, err := mergeSources(value)
			if err != nil {
				return nil, err
			}
			for _, source := range sources {
				merged, err := resolvedMappingPairs(source)
				if err != nil {
					return nil, err
				}
				for _, pair := range merged {
					if explicit[pair.key] {
						continue
					}
					appendPair(pair.key, pair.value)
				}
			}
			continue
		}
		keyString, err := mappingKeyString(key)
		if err != nil {
			return nil, err
		}
		appendPair(keyString, value)
	}
	return pairs, nil
}

func mappingKeyString(key *yaml.Node) (string, error) {
	node := key
	if node.Kind == yaml.AliasNode {
		if node.Alias == nil {
			return "", fmt.Errorf("hako: YAML alias key has no anchor")
		}
		node = node.Alias
	}
	if node.Kind != yaml.ScalarNode {
		return "", fmt.Errorf("hako: YAML mapping key must be a scalar")
	}
	return node.Value, nil
}

func isMergeKey(key *yaml.Node) bool {
	return key.Kind == yaml.ScalarNode && key.Tag == "!!merge"
}

func mergeSources(value *yaml.Node) ([]*yaml.Node, error) {
	switch value.Kind {
	case yaml.AliasNode:
		if value.Alias == nil || value.Alias.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("hako: YAML merge key must reference a mapping")
		}
		return []*yaml.Node{value.Alias}, nil
	case yaml.MappingNode:
		return []*yaml.Node{value}, nil
	case yaml.SequenceNode:
		sources := make([]*yaml.Node, 0, len(value.Content))
		for _, item := range value.Content {
			resolved := item
			if resolved.Kind == yaml.AliasNode {
				resolved = resolved.Alias
			}
			if resolved == nil || resolved.Kind != yaml.MappingNode {
				return nil, fmt.Errorf("hako: YAML merge key must reference a mapping")
			}
			sources = append(sources, resolved)
		}
		return sources, nil
	default:
		return nil, fmt.Errorf("hako: YAML merge key must reference a mapping")
	}
}

func JSONToYaml(rawJSON string) (*StringBox, error) {
	if err := validateConfigurationJSONInput(rawJSON); err != nil {
		return nil, bridgeSafeError(err)
	}
	decoder := json.NewDecoder(strings.NewReader(rawJSON))
	decoder.UseNumber()
	rootNode, err := decodeJSONValueAsYAMLNode(decoder, 0)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: decode JSON: %w", err))
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return nil, bridgeSafeError(fmt.Errorf("hako: decode trailing JSON: %w", err))
		}
		return nil, bridgeSafeError(fmt.Errorf("hako: JSON configuration must contain exactly one value"))
	}
	if rootNode.Kind != yaml.MappingNode {
		return nil, bridgeSafeError(fmt.Errorf("hako: JSON configuration root must be an object"))
	}

	document := yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{rootNode}}
	var output bytes.Buffer
	encoder := yaml.NewEncoder(&output)
	encoder.SetIndent(2)
	if err := encoder.Encode(&document); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: encode JSON configuration as YAML: %w", err))
	}
	if err := encoder.Close(); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("hako: finish YAML encoding: %w", err))
	}
	if err := validateConfigurationResult(output.String()); err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(output.String()), nil
}

const maximumJSONNestingDepth = 10000

func decodeJSONValueAsYAMLNode(decoder *json.Decoder, depth int) (*yaml.Node, error) {
	if depth > maximumJSONNestingDepth {
		return nil, fmt.Errorf("hako: JSON is nested deeper than %d levels", maximumJSONNestingDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	return jsonTokenAsYAMLNode(token, decoder, depth)
}

func jsonTokenAsYAMLNode(token json.Token, decoder *json.Decoder, depth int) (*yaml.Node, error) {
	switch typed := token.(type) {
	case json.Delim:
		switch typed {
		case '{':
			node := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			seen := make(map[string]bool)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, fmt.Errorf("hako: JSON object key must be a string")
				}
				if seen[key] {
					return nil, fmt.Errorf("hako: duplicate JSON object key %q", key)
				}
				seen[key] = true
				value, err := decodeJSONValueAsYAMLNode(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content,
					&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
					value,
				)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return node, nil
		case '[':
			node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
			for decoder.More() {
				item, err := decodeJSONValueAsYAMLNode(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content, item)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, err
			}
			return node, nil
		default:
			return nil, fmt.Errorf("hako: unexpected JSON delimiter %q", typed)
		}
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: typed}, nil
	case json.Number:
		tag := "!!int"
		if strings.ContainsAny(typed.String(), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: typed.String()}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(typed)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	default:
		return nil, fmt.Errorf("hako: unsupported JSON value type %T", token)
	}
}
