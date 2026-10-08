use sentinel_ingest::{EventBus, ScenarioGenerator, ScenarioType};
use sentinel_storage::{EventFilterQuery, EventStore};

#[tokio::test]
async fn test_end_to_end_synthetic_to_eventbus_pipeline() {
    let bus = EventBus::new(100);
    let mut receiver = bus.subscribe();
    let store = EventStore::new();

    let events = ScenarioGenerator::generate_scenario_events(ScenarioType::FullMultiStageAttack);
    assert!(!events.is_empty(), "Should generate events from demo fixture");

    for ev in &events {
        store.insert_event(ev.clone());
        let _ = bus.publish(ev.clone());
    }

    // Verify storage insertion
    assert_eq!(store.count_events(), events.len());

    // Verify filter queries
    let filter = EventFilterQuery {
        action: Some("CreateAccessKey".into()),
        ..Default::default()
    };
    let filtered = store.list_events_filtered(&filter);
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].action, "CreateAccessKey");

    // Verify event bus broadcast receipt
    let received = receiver.recv().await.expect("Should receive event from bus");
    assert_eq!(received.action, events[0].action);
}
