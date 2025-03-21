use std::sync::Arc;

use apollo_federation::query_plan as next;

use crate::query_planner::plan;
use crate::query_planner::rewrites;
use crate::query_planner::subscription;

pub(crate) fn convert_root_query_plan_node(js: &next::QueryPlan) -> Option<plan::PlanNode> {
    let next::QueryPlan {
        node,
        statistics: _,
    } = js;
    option(node)
}

impl From<&'_ next::TopLevelPlanNode> for plan::PlanNode {
    fn from(value: &'_ next::TopLevelPlanNode) -> Self {
        match value {
            next::TopLevelPlanNode::Subscription(node) => node.into(),
            next::TopLevelPlanNode::Fetch(node) => node.into(),
            next::TopLevelPlanNode::Sequence(node) => node.into(),
            next::TopLevelPlanNode::Parallel(node) => node.into(),
            next::TopLevelPlanNode::Flatten(node) => node.into(),
            next::TopLevelPlanNode::Defer(node) => node.into(),
            next::TopLevelPlanNode::Condition(node) => node.as_ref().into(),
        }
    }
}

impl From<&'_ next::PlanNode> for plan::PlanNode {
    fn from(value: &'_ next::PlanNode) -> Self {
        match value {
            next::PlanNode::Fetch(node) => node.into(),
            next::PlanNode::Sequence(node) => node.into(),
            next::PlanNode::Parallel(node) => node.into(),
            next::PlanNode::Flatten(node) => node.into(),
            next::PlanNode::Defer(node) => node.into(),
            next::PlanNode::Condition(node) => node.as_ref().into(),
        }
    }
}
impl From<&'_ Box<next::PlanNode>> for plan::PlanNode {
    fn from(value: &'_ Box<next::PlanNode>) -> Self {
        value.as_ref().into()
    }
}

impl From<&'_ next::SubscriptionNode> for plan::PlanNode {
    fn from(value: &'_ next::SubscriptionNode) -> Self {
        let next::SubscriptionNode { primary, rest } = value;
        Self::Subscription {
            primary: primary.as_ref().into(),
            rest: option(rest).map(Box::new),
        }
    }
}

impl From<&'_ Box<next::FetchNode>> for plan::PlanNode {
    fn from(value: &'_ Box<next::FetchNode>) -> Self {
        let next::FetchNode {
            subgraph_name,
            id,
            variable_usages,
            requires,
            operation_document,
            operation_name,
            operation_kind,
            input_rewrites,
            output_rewrites,
            context_rewrites,
        } = &**value;
        Self::Fetch(super::fetch::FetchNode {
            service_name: subgraph_name.clone(),
            requires: requires.clone(),
            variable_usages: variable_usages.iter().map(|v| v.clone().into()).collect(),
            operation: operation_document.clone(),
            operation_name: operation_name.clone().map(|n| n.into()),
            operation_kind: (*operation_kind).into(),
            id: id.map(|id| id.to_string()),
            input_rewrites: option_vec(input_rewrites),
            output_rewrites: option_vec(output_rewrites),
            context_rewrites: option_vec(context_rewrites),
            schema_aware_hash: Default::default(),
            authorization: Default::default(),
        })
    }
}

impl From<&'_ next::SequenceNode> for plan::PlanNode {
    fn from(value: &'_ next::SequenceNode) -> Self {
        let next::SequenceNode { nodes } = value;
        Self::Sequence { nodes: vec(nodes) }
    }
}

impl From<&'_ next::ParallelNode> for plan::PlanNode {
    fn from(value: &'_ next::ParallelNode) -> Self {
        let next::ParallelNode { nodes } = value;
        Self::Parallel { nodes: vec(nodes) }
    }
}

impl From<&'_ next::FlattenNode> for plan::PlanNode {
    fn from(value: &'_ next::FlattenNode) -> Self {
        let next::FlattenNode { path, node } = value;
        Self::Flatten(plan::FlattenNode {
            path: crate::json_ext::Path(vec(path)),
            node: Box::new(node.into()),
        })
    }
}

impl From<&'_ next::DeferNode> for plan::PlanNode {
    fn from(value: &'_ next::DeferNode) -> Self {
        let next::DeferNode { primary, deferred } = value;
        Self::Defer {
            primary: primary.into(),
            deferred: vec(deferred),
        }
    }
}

impl From<&'_ next::ConditionNode> for plan::PlanNode {
    fn from(value: &'_ next::ConditionNode) -> Self {
        let next::ConditionNode {
            condition_variable,
            if_clause,
            else_clause,
        } = value;
        Self::Condition {
            condition: condition_variable.to_string(),
            if_clause: if_clause.as_ref().map(Into::into).map(Box::new),
            else_clause: else_clause.as_ref().map(Into::into).map(Box::new),
        }
    }
}

impl From<&'_ next::FetchNode> for subscription::SubscriptionNode {
    fn from(value: &'_ next::FetchNode) -> Self {
        let next::FetchNode {
            subgraph_name,
            id: _,
            variable_usages,
            requires: _,
            operation_document,
            operation_name,
            operation_kind,
            input_rewrites,
            output_rewrites,
            context_rewrites: _,
        } = value;
        Self {
            service_name: subgraph_name.clone(),
            variable_usages: variable_usages.iter().map(|v| v.clone().into()).collect(),
            operation: operation_document.clone(),
            operation_name: operation_name.clone().map(|n| n.into()),
            operation_kind: (*operation_kind).into(),
            input_rewrites: option_vec(input_rewrites),
            output_rewrites: option_vec(output_rewrites),
        }
    }
}

impl From<&'_ next::PrimaryDeferBlock> for plan::Primary {
    fn from(value: &'_ next::PrimaryDeferBlock) -> Self {
        let next::PrimaryDeferBlock {
            sub_selection,
            node,
        } = value;
        Self {
            node: option(node).map(Box::new),
            subselection: sub_selection.clone(),
        }
    }
}

impl From<&'_ next::DeferredDeferBlock> for plan::DeferredNode {
    fn from(value: &'_ next::DeferredDeferBlock) -> Self {
        let next::DeferredDeferBlock {
            depends,
            label,
            query_path,
            sub_selection,
            node,
        } = value;
        Self {
            depends: vec(depends),
            label: label.clone(),
            query_path: crate::json_ext::Path(
                query_path
                    .iter()
                    .map(|e| match e {
                        next::QueryPathElement::Field { response_key } =>
                        // TODO: type conditioned fetching once it s available in the rust planner
                        {
                            crate::graphql::JsonPathElement::Key(response_key.to_string(), None)
                        }

                        next::QueryPathElement::InlineFragment { type_condition } => {
                            crate::graphql::JsonPathElement::Fragment(type_condition.to_string())
                        }
                    })
                    .collect(),
            ),
            node: option(node).map(Arc::new),
            subselection: sub_selection.clone(),
        }
    }
}

impl From<&'_ next::DeferredDependency> for plan::Depends {
    fn from(value: &'_ next::DeferredDependency) -> Self {
        let next::DeferredDependency { id } = value;
        Self { id: id.clone() }
    }
}

impl From<&'_ Arc<next::FetchDataRewrite>> for rewrites::DataRewrite {
    fn from(value: &'_ Arc<next::FetchDataRewrite>) -> Self {
        match value.as_ref() {
            next::FetchDataRewrite::ValueSetter(setter) => Self::ValueSetter(setter.into()),
            next::FetchDataRewrite::KeyRenamer(renamer) => Self::KeyRenamer(renamer.into()),
        }
    }
}

impl From<&'_ next::FetchDataValueSetter> for rewrites::DataValueSetter {
    fn from(value: &'_ next::FetchDataValueSetter) -> Self {
        let next::FetchDataValueSetter { path, set_value_to } = value;
        Self {
            path: crate::json_ext::Path(vec(path)),
            set_value_to: set_value_to.clone(),
        }
    }
}

impl From<&'_ next::FetchDataKeyRenamer> for rewrites::DataKeyRenamer {
    fn from(value: &'_ next::FetchDataKeyRenamer) -> Self {
        let next::FetchDataKeyRenamer {
            path,
            rename_key_to,
        } = value;
        Self {
            path: crate::json_ext::Path(vec(path)),
            rename_key_to: rename_key_to.clone(),
        }
    }
}

impl From<&'_ next::FetchDataPathElement> for crate::json_ext::PathElement {
    fn from(value: &'_ next::FetchDataPathElement) -> Self {
        // TODO: Go all in on Name eventually
        match value {
            next::FetchDataPathElement::Key(name, conditions) => Self::Key(
                name.to_string(),
                conditions
                    .as_ref()
                    .map(|conditions| conditions.iter().map(|c| c.to_string()).collect()),
            ),
            next::FetchDataPathElement::AnyIndex(conditions) => Self::Flatten(
                conditions
                    .as_ref()
                    .map(|conditions| conditions.iter().map(|c| c.to_string()).collect()),
            ),
            next::FetchDataPathElement::TypenameEquals(value) => Self::Fragment(value.to_string()),
            next::FetchDataPathElement::Parent => Self::Key("..".to_owned(), None),
        }
    }
}

fn vec<'a, T, U>(value: &'a [T]) -> Vec<U>
where
    U: From<&'a T>,
{
    value.iter().map(Into::into).collect()
}

fn option<'a, T, U>(value: &'a Option<T>) -> Option<U>
where
    U: From<&'a T>,
{
    value.as_ref().map(Into::into)
}

fn option_vec<'a, T, U>(value: &'a [T]) -> Option<Vec<U>>
where
    U: From<&'a T>,
{
    if value.is_empty() {
        None
    } else {
        Some(vec(value))
    }
}
