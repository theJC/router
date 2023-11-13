use std::collections::HashSet;
use std::iter;

use apollo_compiler::ast::DirectiveList;
use apollo_compiler::ast::{
    Argument, Directive, DirectiveDefinition, DirectiveLocation, EnumValueDefinition,
    FieldDefinition, NamedType, Type, Value,
};
use apollo_compiler::schema::{
    Component, EnumType, ExtendedType, InputObjectType, InputValueDefinition, InterfaceType, Name,
    ObjectType, ScalarType, UnionType,
};
use apollo_compiler::{name, Node, NodeStr, Schema};
use indexmap::map::Entry::{Occupied, Vacant};
use indexmap::map::Iter;
use indexmap::{IndexMap, IndexSet};

use crate::subgraph::Subgraph;

type MergeWarning = &'static str;
type MergeError = &'static str;

struct Merger {
    errors: Vec<MergeError>,
    composition_hints: Vec<MergeWarning>,
}

pub struct MergeSuccess {
    pub schema: Schema,
    pub composition_hints: Vec<MergeWarning>,
}

pub struct MergeFailure {
    pub schema: Option<Schema>,
    pub errors: Vec<MergeError>,
    pub composition_hints: Vec<MergeWarning>,
}

pub fn merge_subgraphs(subgraphs: Vec<&Subgraph>) -> Result<MergeSuccess, MergeFailure> {
    let mut merger = Merger::new();
    merger.merge(subgraphs)
}

impl Merger {
    fn new() -> Self {
        Merger {
            composition_hints: Vec::new(),
            errors: Vec::new(),
        }
    }
    fn merge(&mut self, subgraphs: Vec<&Subgraph>) -> Result<MergeSuccess, MergeFailure> {
        let mut subgraphs = subgraphs.clone();
        subgraphs.sort_by(|s1, s2| s1.name.cmp(&s2.name));
        let mut subgraphs_and_enum_values: Vec<(&Subgraph, Name)> = Vec::new();
        for subgraph in &subgraphs {
            // TODO: Implement JS codebase's name transform (which always generates a valid GraphQL
            // name and avoids collisions).
            if let Ok(subgraph_name) = Name::new(&subgraph.name.to_uppercase()) {
                subgraphs_and_enum_values.push((*subgraph, subgraph_name));
            } else {
                self.errors
                    .push("Subgraph name couldn't be transformed into valid GraphQL name");
            }
        }
        if !self.errors.is_empty() {
            return Err(MergeFailure {
                schema: None,
                composition_hints: self.composition_hints.to_owned(),
                errors: self.errors.to_owned(),
            });
        }

        let mut supergraph = Schema::new();
        // TODO handle @compose

        // add core features
        // TODO verify federation versions across subgraphs
        add_core_feature_link(&mut supergraph);
        add_core_feature_join(&mut supergraph, &subgraphs_and_enum_values);

        // create stubs
        for (subgraph, subgraph_name) in &subgraphs_and_enum_values {
            self.merge_schema(&mut supergraph, subgraph);
            // TODO merge directives

            for (key, value) in &subgraph.schema.types {
                if value.is_built_in() || !is_mergeable_type(key) {
                    // skip built-ins and federation specific types
                    continue;
                }

                match value {
                    ExtendedType::Enum(value) => self.merge_enum_type(
                        &mut supergraph.types,
                        subgraph_name.clone(),
                        key.clone(),
                        value,
                    ),
                    ExtendedType::InputObject(value) => self.merge_input_object_type(
                        &mut supergraph.types,
                        subgraph_name.clone(),
                        key.clone(),
                        value,
                    ),
                    ExtendedType::Interface(value) => self.merge_interface_type(
                        &mut supergraph.types,
                        subgraph_name.clone(),
                        key.clone(),
                        value,
                    ),
                    ExtendedType::Object(value) => self.merge_object_type(
                        &mut supergraph.types,
                        subgraph_name.clone(),
                        key.clone(),
                        value,
                    ),
                    ExtendedType::Union(value) => self.merge_union_type(
                        &mut supergraph.types,
                        subgraph_name.clone(),
                        key.clone(),
                        value,
                    ),
                    ExtendedType::Scalar(_value) => {
                        // DO NOTHING
                    }
                }
            }

            // merge executable directives
            for (_, directive) in subgraph.schema.directive_definitions.iter() {
                if is_executable_directive(directive) {
                    merge_directive(&mut supergraph.directive_definitions, directive);
                }
            }
        }

        if self.errors.is_empty() {
            Ok(MergeSuccess {
                schema: supergraph,
                composition_hints: self.composition_hints.to_owned(),
            })
        } else {
            Err(MergeFailure {
                schema: Some(supergraph),
                composition_hints: self.composition_hints.to_owned(),
                errors: self.errors.to_owned(),
            })
        }
    }

    fn merge_descriptions<T: Eq + Clone>(&mut self, merged: &mut Option<T>, new: &Option<T>) {
        match (&mut *merged, new) {
            (_, None) => {}
            (None, Some(_)) => *merged = new.clone(),
            (Some(a), Some(b)) => {
                if a != b {
                    // TODO add info about type and from/to subgraph
                    self.composition_hints.push("conflicting descriptions");
                }
            }
        }
    }

    fn merge_schema(&mut self, supergraph_schema: &mut Schema, subgraph: &Subgraph) {
        let supergraph_def = &mut supergraph_schema.schema_definition.make_mut();
        let subgraph_def = &subgraph.schema.schema_definition;
        self.merge_descriptions(&mut supergraph_def.description, &subgraph_def.description);

        if subgraph_def.query.is_some() {
            supergraph_def.query = subgraph_def.query.clone();
            // TODO mismatch on query types
        }
        if subgraph_def.mutation.is_some() {
            supergraph_def.mutation = subgraph_def.mutation.clone();
            // TODO mismatch on mutation types
        }
        if subgraph_def.subscription.is_some() {
            supergraph_def.subscription = subgraph_def.subscription.clone();
            // TODO mismatch on subscription types
        }
    }

    fn merge_enum_type(
        &mut self,
        types: &mut IndexMap<NamedType, ExtendedType>,
        subgraph_name: Name,
        enum_name: NamedType,
        enum_type: &Node<EnumType>,
    ) {
        let existing_type = types
            .entry(enum_name.clone())
            .or_insert(copy_enum_type(enum_name, enum_type));
        if let ExtendedType::Enum(e) = existing_type {
            let join_type_directives =
                join_type_applied_directive(subgraph_name.clone(), iter::empty(), false);
            e.make_mut().directives.extend(join_type_directives);

            self.merge_descriptions(&mut e.make_mut().description, &enum_type.description);

            // TODO we need to merge those fields LAST so we know whether enum is used as input/output/both as different merge rules will apply
            // below logic only works for output enums
            for (enum_value_name, enum_value) in enum_type.values.iter() {
                let ev = e
                    .make_mut()
                    .values
                    .entry(enum_value_name.clone())
                    .or_insert(Component::new(EnumValueDefinition {
                        value: enum_value.value.clone(),
                        description: None,
                        directives: Default::default(),
                    }));
                self.merge_descriptions(&mut ev.make_mut().description, &enum_value.description);
                ev.make_mut().directives.push(Node::new(Directive {
                    name: name!("join__enumValue"),
                    arguments: vec![
                        (Node::new(Argument {
                            name: name!("graph"),
                            value: Node::new(Value::Enum(subgraph_name.clone())),
                        })),
                    ],
                }));
            }
        } else {
            // TODO - conflict
        }
    }

    fn merge_input_object_type(
        &mut self,
        types: &mut IndexMap<NamedType, ExtendedType>,
        subgraph_name: Name,
        input_object_name: NamedType,
        input_object: &Node<InputObjectType>,
    ) {
        let existing_type = types
            .entry(input_object_name.clone())
            .or_insert(copy_input_object_type(input_object_name, input_object));
        if let ExtendedType::InputObject(obj) = existing_type {
            let join_type_directives =
                join_type_applied_directive(subgraph_name, iter::empty(), false);
            let mutable_object = obj.make_mut();
            mutable_object.directives.extend(join_type_directives);

            for (field_name, _field) in input_object.fields.iter() {
                let existing_field = mutable_object.fields.entry(field_name.clone());
                match existing_field {
                    Vacant(_i) => {
                        // TODO warning - mismatch on input fields
                    }
                    Occupied(_i) => {
                        // merge_options(&i.get_mut().description, &field.description);
                        // TODO check description
                        // TODO check type
                        // TODO check default value
                        // TODO process directives
                    }
                }
            }
        } else {
            // TODO conflict on type
        }
    }

    fn merge_interface_type(
        &mut self,
        types: &mut IndexMap<NamedType, ExtendedType>,
        subgraph_name: Name,
        interface_name: NamedType,
        interface: &Node<InterfaceType>,
    ) {
        let existing_type = types
            .entry(interface_name.clone())
            .or_insert(copy_interface_type(interface_name, interface));
        if let ExtendedType::Interface(intf) = existing_type {
            let key_directives = interface.directives.get_all("key");
            let join_type_directives =
                join_type_applied_directive(subgraph_name, key_directives, false);
            let mutable_intf = intf.make_mut();
            mutable_intf.directives.extend(join_type_directives);

            for (field_name, field) in interface.fields.iter() {
                let existing_field = mutable_intf.fields.entry(field_name.clone());
                match existing_field {
                    Vacant(i) => {
                        // TODO warning mismatch missing fields
                        i.insert(Component::new(FieldDefinition {
                            name: field.name.clone(),
                            description: field.description.clone(),
                            arguments: vec![],
                            ty: field.ty.clone(),
                            directives: Default::default(),
                        }));
                    }
                    Occupied(_i) => {
                        // TODO check description
                        // TODO check type
                        // TODO check default value
                        // TODO process directives
                    }
                }
            }
        } else {
            // TODO conflict on type
        }
    }

    fn merge_object_type(
        &mut self,
        types: &mut IndexMap<NamedType, ExtendedType>,
        subgraph_name: Name,
        object_name: NamedType,
        object: &Node<ObjectType>,
    ) {
        let is_interface_object = object.directives.has("interfaceObject");
        let existing_type = types
            .entry(object_name.clone())
            .or_insert(copy_object_type_stub(
                object_name.clone(),
                object,
                is_interface_object,
            ));
        if let ExtendedType::Object(obj) = existing_type {
            let key_fields: HashSet<&str> = parse_keys(object.directives.get_all("key"));
            let is_join_field = !key_fields.is_empty() || object_name == "Query";
            let key_directives = object.directives.get_all("key");
            let join_type_directives =
                join_type_applied_directive(subgraph_name.clone(), key_directives, false);
            let mutable_object = obj.make_mut();
            mutable_object.directives.extend(join_type_directives);
            self.merge_descriptions(&mut mutable_object.description, &object.description);
            object.implements_interfaces.iter().for_each(|intf_name| {
                // IndexSet::insert deduplicates
                mutable_object
                    .implements_interfaces
                    .insert(intf_name.clone());
                let join_implements_directive =
                    join_type_implements(subgraph_name.clone(), intf_name);
                mutable_object.directives.push(join_implements_directive);
            });

            for (field_name, field) in object.fields.iter() {
                // skip federation built-in queries
                if field_name == "_service" || field_name == "_entities" {
                    continue;
                }

                let existing_field = mutable_object.fields.entry(field_name.clone());
                let supergraph_field = match existing_field {
                    Occupied(f) => {
                        // check description
                        // check type
                        // check args
                        f.into_mut()
                    }
                    Vacant(f) => f.insert(Component::new(FieldDefinition {
                        name: field.name.clone(),
                        description: field.description.clone(),
                        arguments: vec![],
                        directives: Default::default(),
                        ty: field.ty.clone(),
                    })),
                };
                self.merge_descriptions(
                    &mut supergraph_field.make_mut().description,
                    &field.description,
                );
                let mut existing_args = supergraph_field.arguments.iter();
                for arg in field.arguments.iter() {
                    if let Some(_existing_arg) = &existing_args.find(|a| a.name == arg.name) {
                    } else {
                        // TODO mismatch no args
                    }
                }

                if is_join_field {
                    let is_key_field = key_fields.contains(field_name.as_str());
                    if !is_key_field {
                        let requires_directive_option =
                            Option::and_then(field.directives.get_all("requires").next(), |p| {
                                let requires_fields =
                                    directive_string_arg_value(p, "fields").unwrap();
                                Some(requires_fields.as_str())
                            });
                        let provides_directive_option =
                            Option::and_then(field.directives.get_all("provides").next(), |p| {
                                let provides_fields =
                                    directive_string_arg_value(p, "fields").unwrap();
                                Some(provides_fields.as_str())
                            });
                        let external_field = field.directives.get_all("external").next().is_some();
                        let join_field_directive = join_field_applied_directive(
                            subgraph_name.clone(),
                            requires_directive_option,
                            provides_directive_option,
                            external_field,
                        );

                        supergraph_field
                            .make_mut()
                            .directives
                            .push(Node::new(join_field_directive));
                    }
                }
            }
        } else if let ExtendedType::Interface(intf) = existing_type {
            // TODO support interface object
            let key_directives = object.directives.get_all("key");
            let join_type_directives =
                join_type_applied_directive(subgraph_name, key_directives, true);
            intf.make_mut().directives.extend(join_type_directives);
        };
        // TODO merge fields
    }

    fn merge_union_type(
        &mut self,
        types: &mut IndexMap<NamedType, ExtendedType>,
        subgraph_name: Name,
        union_name: NamedType,
        union: &Node<UnionType>,
    ) {
        let existing_type = types.entry(union_name.clone()).or_insert(copy_union_type(
            union_name.clone(),
            union.description.clone(),
        ));
        if let ExtendedType::Union(u) = existing_type {
            let join_type_directives =
                join_type_applied_directive(subgraph_name.clone(), iter::empty(), false);
            u.make_mut().directives.extend(join_type_directives);

            for union_member in union.members.iter() {
                // IndexSet::insert deduplicates
                u.make_mut().members.insert(union_member.clone());
                u.make_mut().directives.push(Component::new(Directive {
                    name: name!("join__unionMember"),
                    arguments: vec![
                        Node::new(Argument {
                            name: name!("graph"),
                            value: Node::new(Value::Enum(subgraph_name.clone())),
                        }),
                        Node::new(Argument {
                            name: name!("member"),
                            value: Node::new(Value::String(NodeStr::new(union_member))),
                        }),
                    ],
                }));
            }
        }
    }
}

const EXECUTABLE_DIRECTIVE_LOCATIONS: [DirectiveLocation; 8] = [
    DirectiveLocation::Query,
    DirectiveLocation::Mutation,
    DirectiveLocation::Subscription,
    DirectiveLocation::Field,
    DirectiveLocation::FragmentDefinition,
    DirectiveLocation::FragmentSpread,
    DirectiveLocation::InlineFragment,
    DirectiveLocation::VariableDefinition,
];
fn is_executable_directive(directive: &Node<DirectiveDefinition>) -> bool {
    directive
        .locations
        .iter()
        .any(|loc| EXECUTABLE_DIRECTIVE_LOCATIONS.contains(loc))
}

// TODO handle federation specific types - skip if any of the link/fed spec
// TODO this info should be coming from other module
const FEDERATION_TYPES: [&str; 4] = ["_Any", "_Entity", "_Service", "@key"];
fn is_mergeable_type(type_name: &str) -> bool {
    if type_name.starts_with("federation__") || type_name.starts_with("link__") {
        return false;
    }
    !FEDERATION_TYPES.contains(&type_name)
}

fn copy_enum_type(enum_name: Name, enum_type: &Node<EnumType>) -> ExtendedType {
    ExtendedType::Enum(Node::new(EnumType {
        description: enum_type.description.clone(),
        name: enum_name,
        directives: Default::default(),
        values: IndexMap::new(),
    }))
}

fn copy_input_object_type(
    input_object_name: Name,
    input_object: &Node<InputObjectType>,
) -> ExtendedType {
    let mut new_input_object = InputObjectType {
        description: input_object.description.clone(),
        name: input_object_name,
        directives: Default::default(),
        fields: IndexMap::new(),
    };

    for (field_name, input_field) in input_object.fields.iter() {
        new_input_object.fields.insert(
            field_name.clone(),
            Component::new(InputValueDefinition {
                name: input_field.name.clone(),
                description: input_field.description.clone(),
                directives: Default::default(),
                ty: input_field.ty.clone(),
                default_value: input_field.default_value.clone(),
            }),
        );
    }

    ExtendedType::InputObject(Node::new(new_input_object))
}

fn copy_interface_type(interface_name: Name, interface: &Node<InterfaceType>) -> ExtendedType {
    let new_interface = InterfaceType {
        description: interface.description.clone(),
        name: interface_name,
        directives: Default::default(),
        fields: copy_fields(interface.fields.iter()),
        implements_interfaces: interface.implements_interfaces.clone(),
    };
    ExtendedType::Interface(Node::new(new_interface))
}

fn copy_object_type_stub(
    object_name: Name,
    object: &Node<ObjectType>,
    is_interface_object: bool,
) -> ExtendedType {
    if is_interface_object {
        let new_interface = InterfaceType {
            description: object.description.clone(),
            name: object_name,
            directives: Default::default(),
            fields: copy_fields(object.fields.iter()),
            implements_interfaces: object.implements_interfaces.clone(),
        };
        ExtendedType::Interface(Node::new(new_interface))
    } else {
        let new_object = ObjectType {
            description: object.description.clone(),
            name: object_name,
            directives: Default::default(),
            fields: copy_fields(object.fields.iter()),
            implements_interfaces: object.implements_interfaces.clone(),
        };
        ExtendedType::Object(Node::new(new_object))
    }
}

fn copy_fields(
    fields_to_copy: Iter<Name, Component<FieldDefinition>>,
) -> IndexMap<Name, Component<FieldDefinition>> {
    let mut new_fields: IndexMap<Name, Component<FieldDefinition>> = IndexMap::new();
    for (field_name, field) in fields_to_copy {
        // skip federation built-in queries
        if field_name == "_service" || field_name == "_entities" {
            continue;
        }
        let args: Vec<Node<InputValueDefinition>> = field
            .arguments
            .iter()
            .map(|a| {
                Node::new(InputValueDefinition {
                    name: a.name.clone(),
                    description: a.description.clone(),
                    directives: Default::default(),
                    ty: a.ty.clone(),
                    default_value: a.default_value.clone(),
                })
            })
            .collect();
        let new_field = Component::new(FieldDefinition {
            name: field.name.clone(),
            description: field.description.clone(),
            directives: Default::default(),
            arguments: args,
            ty: field.ty.clone(),
        });

        new_fields.insert(field_name.clone(), new_field);
    }
    new_fields
}

fn copy_union_type(union_name: Name, description: Option<NodeStr>) -> ExtendedType {
    ExtendedType::Union(Node::new(UnionType {
        description,
        name: union_name,
        directives: Default::default(),
        members: IndexSet::new(),
    }))
}

fn join_type_applied_directive<'a>(
    subgraph_name: Name,
    key_directives: impl Iterator<Item = &'a Component<Directive>> + Sized,
    is_interface_object: bool,
) -> Vec<Component<Directive>> {
    let mut join_type_directive = Directive {
        name: name!("join__type"),
        arguments: vec![Node::new(Argument {
            name: name!("graph"),
            value: Node::new(Value::Enum(subgraph_name)),
        })],
    };
    if is_interface_object {
        join_type_directive.arguments.push(Node::new(Argument {
            name: name!("isInterfaceObject"),
            value: Node::new(Value::Boolean(is_interface_object)),
        }));
    }

    let mut result = vec![];
    for key_directive in key_directives {
        let mut join_type_directive_with_key = join_type_directive.clone();
        let field_set = directive_string_arg_value(key_directive, "fields").unwrap();
        join_type_directive_with_key
            .arguments
            .push(Node::new(Argument {
                name: name!("key"),
                value: Node::new(Value::String(NodeStr::new(field_set.as_str()))),
            }));

        let resolvable = directive_bool_arg_value(key_directive, "resolvable").unwrap_or(&true);
        if !resolvable {
            join_type_directive_with_key
                .arguments
                .push(Node::new(Argument {
                    name: name!("resolvable"),
                    value: Node::new(Value::Boolean(false)),
                }));
        }
        result.push(join_type_directive_with_key)
    }
    if result.is_empty() {
        result.push(join_type_directive)
    }
    result
        .into_iter()
        .map(Component::new)
        .collect::<Vec<Component<Directive>>>()
}

fn join_type_implements(subgraph_name: Name, intf_name: &str) -> Component<Directive> {
    Component::new(Directive {
        name: name!("join__implements"),
        arguments: vec![
            Node::new(Argument {
                name: name!("graph"),
                value: Node::new(Value::Enum(subgraph_name)),
            }),
            Node::new(Argument {
                name: name!("interface"),
                value: Node::new(Value::String(NodeStr::new(intf_name))),
            }),
        ],
    })
}

fn directive_arg_value<'a>(directive: &'a Directive, arg_name: &'static str) -> Option<&'a Value> {
    directive
        .arguments
        .iter()
        .find(|arg| arg.name == arg_name)
        .map(|arg| arg.value.as_ref())
}

fn directive_string_arg_value<'a>(
    directive: &'a Directive,
    arg_name: &'static str,
) -> Option<&'a NodeStr> {
    match directive_arg_value(directive, arg_name) {
        Some(Value::String(value)) => Some(value),
        _ => None,
    }
}

fn directive_bool_arg_value<'a>(
    directive: &'a Directive,
    arg_name: &'static str,
) -> Option<&'a bool> {
    match directive_arg_value(directive, arg_name) {
        Some(Value::Boolean(value)) => Some(value),
        _ => None,
    }
}

// TODO link spec
fn add_core_feature_link(supergraph: &mut Schema) {
    // @link(url: "https://specs.apollo.dev/link/v1.0")
    supergraph
        .schema_definition
        .make_mut()
        .directives
        .push(Component::new(Directive {
            name: name!("link"),
            arguments: vec![Node::new(Argument {
                name: name!("url"),
                value: Node::new(Value::String(NodeStr::new(
                    "https://specs.apollo.dev/link/v1.0",
                ))),
            })],
        }));

    let (name, link_purpose_enum) = link_purpose_enum_type();
    supergraph.types.insert(name, link_purpose_enum.into());

    // scalar Import
    let link_import_name = name!("link__Import");
    let link_import_scalar = ExtendedType::Scalar(Node::new(ScalarType {
        directives: Default::default(),
        name: link_import_name.clone(),
        description: None,
    }));
    supergraph
        .types
        .insert(link_import_name, link_import_scalar);

    let link_directive_definition = link_directive_definition();
    supergraph
        .directive_definitions
        .insert(name!("link"), Node::new(link_directive_definition));
}

/// directive @link(url: String, as: String, import: [Import], for: link__Purpose) repeatable on SCHEMA
fn link_directive_definition() -> DirectiveDefinition {
    DirectiveDefinition {
        name: name!("link"),
        description: None,
        arguments: vec![
            Node::new(InputValueDefinition {
                name: name!("url"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("String")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("as"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("String")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("for"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("link__Purpose")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("import"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("link__Import")).list().into(),
                default_value: None,
            }),
        ],
        locations: vec![DirectiveLocation::Schema],
        repeatable: true,
    }
}

/// enum link__Purpose {
///   """
///   \`SECURITY\` features provide metadata necessary to securely resolve fields.
///   """
///   SECURITY
///
///   """
///   \`EXECUTION\` features provide metadata necessary for operation execution.
///   """
///   EXECUTION
/// }
fn link_purpose_enum_type() -> (Name, EnumType) {
    let link_purpose_name = name!("link__Purpose");
    let mut link_purpose_enum = EnumType {
        description: None,
        name: link_purpose_name.clone(),
        directives: Default::default(),
        values: IndexMap::new(),
    };
    let link_purpose_security_value = EnumValueDefinition {
        description: Some(NodeStr::new(
            r"SECURITY features provide metadata necessary to securely resolve fields.",
        )),
        directives: Default::default(),
        value: name!("SECURITY"),
    };
    let link_purpose_execution_value = EnumValueDefinition {
        description: Some(NodeStr::new(
            r"EXECUTION features provide metadata necessary for operation execution.",
        )),
        directives: Default::default(),
        value: name!("EXECUTION"),
    };
    link_purpose_enum.values.insert(
        link_purpose_security_value.value.clone(),
        Component::new(link_purpose_security_value),
    );
    link_purpose_enum.values.insert(
        link_purpose_execution_value.value.clone(),
        Component::new(link_purpose_execution_value),
    );
    (link_purpose_name, link_purpose_enum)
}

// TODO join spec
fn add_core_feature_join(
    supergraph: &mut Schema,
    subgraphs_and_enum_values: &Vec<(&Subgraph, Name)>,
) {
    // @link(url: "https://specs.apollo.dev/join/v0.3", for: EXECUTION)
    supergraph
        .schema_definition
        .make_mut()
        .directives
        .push(Component::new(Directive {
            name: name!("link"),
            arguments: vec![
                Node::new(Argument {
                    name: name!("url"),
                    value: Node::new(Value::String(NodeStr::new(
                        "https://specs.apollo.dev/join/v0.3",
                    ))),
                }),
                Node::new(Argument {
                    name: name!("for"),
                    value: Node::new(Value::Enum(name!("EXECUTION"))),
                }),
            ],
        }));

    // scalar FieldSet
    let join_field_set_name = name!("join__FieldSet");
    let join_field_set_scalar = ExtendedType::Scalar(Node::new(ScalarType {
        directives: Default::default(),
        name: join_field_set_name.clone(),
        description: None,
    }));
    supergraph
        .types
        .insert(join_field_set_name, join_field_set_scalar);

    let join_graph_directive_definition = join_graph_directive_definition();
    supergraph.directive_definitions.insert(
        join_graph_directive_definition.name.clone(),
        Node::new(join_graph_directive_definition),
    );

    let join_type_directive_definition = join_type_directive_definition();
    supergraph.directive_definitions.insert(
        join_type_directive_definition.name.clone(),
        Node::new(join_type_directive_definition),
    );

    let join_field_directive_definition = join_field_directive_definition();
    supergraph.directive_definitions.insert(
        join_field_directive_definition.name.clone(),
        Node::new(join_field_directive_definition),
    );

    let join_implements_directive_definition = join_implements_directive_definition();
    supergraph.directive_definitions.insert(
        join_implements_directive_definition.name.clone(),
        Node::new(join_implements_directive_definition),
    );

    let join_union_member_directive_definition = join_union_member_directive_definition();
    supergraph.directive_definitions.insert(
        join_union_member_directive_definition.name.clone(),
        Node::new(join_union_member_directive_definition),
    );

    let join_enum_value_directive_definition = join_enum_value_directive_definition();
    supergraph.directive_definitions.insert(
        join_enum_value_directive_definition.name.clone(),
        Node::new(join_enum_value_directive_definition),
    );

    let (name, join_graph_enum_type) = join_graph_enum_type(subgraphs_and_enum_values);
    supergraph.types.insert(name, join_graph_enum_type.into());
}

/// directive @enumValue(graph: join__Graph!) repeatable on ENUM_VALUE
fn join_enum_value_directive_definition() -> DirectiveDefinition {
    DirectiveDefinition {
        name: name!("join__enumValue"),
        description: None,
        arguments: vec![Node::new(InputValueDefinition {
            name: name!("graph"),
            description: None,
            directives: Default::default(),
            ty: Type::Named(name!("join__Graph")).non_null().into(),
            default_value: None,
        })],
        locations: vec![DirectiveLocation::EnumValue],
        repeatable: true,
    }
}

/// directive @field(
///   graph: Graph,
///   requires: FieldSet,
///   provides: FieldSet,
///   type: String,
///   external: Boolean,
///   override: String,
///   usedOverridden: Boolean
/// ) repeatable on FIELD_DEFINITION | INPUT_FIELD_DEFINITION
fn join_field_directive_definition() -> DirectiveDefinition {
    DirectiveDefinition {
        name: name!("join__field"),
        description: None,
        arguments: vec![
            Node::new(InputValueDefinition {
                name: name!("graph"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("join__Graph")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("requires"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("join__FieldSet")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("provides"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("join__FieldSet")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("type"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("String")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("external"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("Boolean")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("override"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("String")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("usedOverridden"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("Boolean")).into(),
                default_value: None,
            }),
        ],
        locations: vec![
            DirectiveLocation::FieldDefinition,
            DirectiveLocation::InputFieldDefinition,
        ],
        repeatable: true,
    }
}

fn join_field_applied_directive(
    subgraph_name: Name,
    requires: Option<&str>,
    provides: Option<&str>,
    external: bool,
) -> Directive {
    let mut join_field_directive = Directive {
        name: name!("join__field"),
        arguments: vec![Node::new(Argument {
            name: name!("graph"),
            value: Node::new(Value::Enum(subgraph_name)),
        })],
    };
    if let Some(required_fields) = requires {
        join_field_directive.arguments.push(Node::new(Argument {
            name: name!("requires"),
            value: Node::new(Value::String(NodeStr::new(required_fields))),
        }));
    }
    if let Some(provided_fields) = provides {
        join_field_directive.arguments.push(Node::new(Argument {
            name: name!("provides"),
            value: Node::new(Value::String(NodeStr::new(provided_fields))),
        }));
    }
    if external {
        join_field_directive.arguments.push(Node::new(Argument {
            name: name!("external"),
            value: Node::new(Value::Boolean(external)),
        }));
    }
    join_field_directive
}

/// directive @graph(name: String!, url: String!) on ENUM_VALUE
fn join_graph_directive_definition() -> DirectiveDefinition {
    DirectiveDefinition {
        name: name!("join__graph"),
        description: None,
        arguments: vec![
            Node::new(InputValueDefinition {
                name: name!("name"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("String")).non_null().into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("url"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("String")).non_null().into(),
                default_value: None,
            }),
        ],
        locations: vec![DirectiveLocation::EnumValue],
        repeatable: false,
    }
}

/// directive @implements(
///   graph: Graph!,
///   interface: String!
/// ) on OBJECT | INTERFACE
fn join_implements_directive_definition() -> DirectiveDefinition {
    DirectiveDefinition {
        name: name!("join__implements"),
        description: None,
        arguments: vec![
            Node::new(InputValueDefinition {
                name: name!("graph"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("join__Graph")).non_null().into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("interface"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("String")).non_null().into(),
                default_value: None,
            }),
        ],
        locations: vec![DirectiveLocation::Interface, DirectiveLocation::Object],
        repeatable: true,
    }
}

/// directive @type(
///   graph: Graph!,
///   key: FieldSet,
///   extension: Boolean! = false,
///   resolvable: Boolean = true,
///   isInterfaceObject: Boolean = false
/// ) repeatable on OBJECT | INTERFACE | UNION | ENUM | INPUT_OBJECT | SCALAR
fn join_type_directive_definition() -> DirectiveDefinition {
    DirectiveDefinition {
        name: name!("join__type"),
        description: None,
        arguments: vec![
            Node::new(InputValueDefinition {
                name: name!("graph"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("join__Graph")).non_null().into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("key"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("join__FieldSet")).into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("extension"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("Boolean")).non_null().into(),
                default_value: Some(Node::new(Value::Boolean(false))),
            }),
            Node::new(InputValueDefinition {
                name: name!("resolvable"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("Boolean")).non_null().into(),
                default_value: Some(Node::new(Value::Boolean(true))),
            }),
            Node::new(InputValueDefinition {
                name: name!("isInterfaceObject"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("Boolean")).non_null().into(),
                default_value: Some(Node::new(Value::Boolean(false))),
            }),
        ],
        locations: vec![
            DirectiveLocation::Enum,
            DirectiveLocation::InputObject,
            DirectiveLocation::Interface,
            DirectiveLocation::Object,
            DirectiveLocation::Scalar,
            DirectiveLocation::Union,
        ],
        repeatable: true,
    }
}

/// directive @unionMember(graph: join__Graph!, member: String!) repeatable on UNION
fn join_union_member_directive_definition() -> DirectiveDefinition {
    DirectiveDefinition {
        name: name!("join__unionMember"),
        description: None,
        arguments: vec![
            Node::new(InputValueDefinition {
                name: name!("graph"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("join__Graph")).non_null().into(),
                default_value: None,
            }),
            Node::new(InputValueDefinition {
                name: name!("member"),
                description: None,
                directives: Default::default(),
                ty: Type::Named(name!("String")).non_null().into(),
                default_value: None,
            }),
        ],
        locations: vec![DirectiveLocation::Union],
        repeatable: true,
    }
}

/// enum Graph
fn join_graph_enum_type(subgraphs_and_enum_values: &Vec<(&Subgraph, Name)>) -> (Name, EnumType) {
    let join_graph_enum_name = name!("join__Graph");
    let mut join_graph_enum_type = EnumType {
        description: None,
        name: join_graph_enum_name.clone(),
        directives: Default::default(),
        values: IndexMap::new(),
    };
    for (s, subgraph_name) in subgraphs_and_enum_values {
        let join_graph_applied_directive = Directive {
            name: name!("join__graph"),
            arguments: vec![
                (Node::new(Argument {
                    name: name!("name"),
                    value: Node::new(Value::String(NodeStr::new(s.name.as_str()))),
                })),
                (Node::new(Argument {
                    name: name!("url"),
                    value: Node::new(Value::String(NodeStr::new(s.url.as_str()))),
                })),
            ],
        };
        let graph = EnumValueDefinition {
            description: None,
            directives: DirectiveList(vec![Node::new(join_graph_applied_directive)]),
            value: subgraph_name.clone(),
        };
        join_graph_enum_type
            .values
            .insert(graph.value.clone(), Component::new(graph));
    }
    (join_graph_enum_name, join_graph_enum_type)
}

fn parse_keys<'a>(
    directives: impl Iterator<Item = &'a Component<Directive>> + Sized,
) -> HashSet<&'a str> {
    HashSet::from_iter(
        directives
            .flat_map(|k| {
                let field_set = directive_string_arg_value(k, "fields").unwrap();
                field_set.split_whitespace()
            })
            .collect::<Vec<&str>>(),
    )
}

fn merge_directive(
    supergraph_directives: &mut IndexMap<Name, Node<DirectiveDefinition>>,
    directive: &Node<DirectiveDefinition>,
) {
    if !supergraph_directives.contains_key(&directive.name.clone()) {
        supergraph_directives.insert(directive.name.clone(), directive.clone());
    }
}
