I need to refactor @/pkcs11 PKCS#11 provider implementation to create a modular, extensible architecture that transforms the current monolithic implementation into a layered system with clear separation of concerns

Design and implement a backend abstraction layer that defines a comprehensive generic interface for all cryptographic operations, enabling any crypto library (OpenSSL, BoringSSL, WolfCrypt, aws-lc, or others) to be seamlessly integrated as the underlying implementation without requiring any modifications to the PKCS#11 protocol logic

Refactor the existing @/pkcs11 codebase into a reusable, crypto-backend-agnostic core library crate that encapsulates all PKCS#11-specific functionality including protocol handling, object lifecycle management, session management, token operations, and attribute processing, designed as a foundational dependency for multiple concrete implementations

Extract and migrate all current nethsm-sdk-rs cryptographic functionality into a new @/pkcs11_impl_nethsm_sdk crate that implements the backend interface and depends on @/pkcs11, providing a complete, production-ready PKCS#11 provider with full nethsm-sdk-rs integration for real-world cryptographic operations

Develop a comprehensive @/pkcs11_impl_mock crate that implements the backend interface and depends on @/pkcs11, offering a fully functional mock implementation with simulated cryptographic operations suitable for testing, development environments, CI/CD pipelines, and scenarios where actual cryptographic security is not required but PKCS#11 compatibility is needed

Ensure both @/pkcs11_impl_mock and @/pkcs11_impl_nethsm_sdk function as complete, standalone PKCS#11 modules that can be directly integrated with any PKCS#11-compatible applications, tools, and libraries for comprehensive provider information queries, key management operations, certificate handling, and all standard cryptographic functions

Design the backend interface to support extensibility for future cryptographic backends while maintaining API stability, implement proper error handling and type safety throughout all layers, ensure thread safety and concurrent access patterns, and maintain backward compatibility where possible

Create a comprehensive project plan with detailed task breakdown, implementation phases, testing strategies, and documentation requirements, then generate and maintain a detailed todo.md file that tracks all tasks with checkboxes, priority levels, dependencies, and completion status, ensuring the todo.md remains current and accurate as tasks are completed so development can be resumed efficiently at any point, focus on implementation end to end than writing just the implementation plan, write todo.md so it can be resumed at any point