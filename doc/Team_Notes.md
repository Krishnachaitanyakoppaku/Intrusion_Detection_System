# IDS DSL Engine - Team Notes

## Project Design Decisions

### Architecture Overview

The IDS DSL Engine follows a modular architecture with clear separation of concerns:

1. **Lexical Analysis** (`lexer.l`): Tokenizes input rules
2. **Syntax Analysis** (`parser.y`): Parses tokens into AST
3. **AST Management** (`ast.h`, `ast.c`): Data structures and operations
4. **Rule Engine** (`engine.h`, `engine.c`): Packet processing and matching
5. **Main Application** (`main.c`): CLI interface and orchestration

### Key Design Decisions

#### 1. AST Structure
- **Decision**: Use linked lists for rules and options
- **Rationale**: Dynamic sizing, easy insertion/deletion
- **Trade-off**: Slightly slower access than arrays, but more flexible

#### 2. Packet Processing
- **Decision**: Use libpcap for packet capture
- **Rationale**: Industry standard, cross-platform, efficient
- **Trade-off**: Requires root privileges, but necessary for raw packet access

#### 3. Rule Matching
- **Decision**: Sequential rule checking
- **Rationale**: Simple, predictable, easy to debug
- **Trade-off**: O(n) complexity, but acceptable for small rule sets

#### 4. Content Matching
- **Decision**: Use simple string matching (strstr)
- **Rationale**: Fast, simple, covers most use cases
- **Trade-off**: No regex support, but can be extended later

## Implementation Notes

### Lexer (lexer.l)
- **Keywords**: alert, log, pass, tcp, udp, icmp, ip
- **Operators**: ->, <>, :, ;, (, )
- **Data Types**: IP addresses, ports, strings, numbers
- **Error Handling**: Basic lexical error reporting

### Parser (parser.y)
- **Grammar**: LL(1) grammar for rule parsing
- **AST Building**: Creates rule structures during parsing
- **Error Recovery**: Basic error reporting with line numbers
- **Options**: Support for msg, content, priority, sid, rev, classtype, reference

### Engine (engine.c)
- **Packet Capture**: Uses pcap_loop for continuous monitoring
- **Protocol Support**: IP, TCP, UDP, ICMP
- **Matching Logic**: Protocol, IP, port, and content matching
- **Alert Generation**: Console output and file logging

## Performance Considerations

### Memory Management
- **Rule Storage**: Dynamic allocation for rules and options
- **Packet Processing**: Temporary packet info structures
- **Cleanup**: Proper memory deallocation on shutdown

### Network Performance
- **Packet Capture**: Single-threaded, blocking I/O
- **Rule Matching**: Sequential processing
- **Alert Generation**: Synchronous logging

### Scalability
- **Rule Count**: Designed for hundreds of rules
- **Packet Rate**: Suitable for moderate network traffic
- **Memory Usage**: Linear growth with rule count

## Security Considerations

### Privilege Requirements
- **Root Access**: Required for raw packet capture
- **Interface Access**: Monitor mode or promiscuous mode
- **File Permissions**: Log file access

### Rule Validation
- **Syntax Checking**: Parser validates rule syntax
- **Semantic Validation**: Basic rule logic validation
- **Error Handling**: Graceful handling of malformed rules

## Testing Strategy

### Unit Testing
- **Parser Testing**: Test rule parsing with various inputs
- **AST Testing**: Verify rule structure creation
- **Engine Testing**: Test packet matching logic

### Integration Testing
- **End-to-End**: Full pipeline from rules to alerts
- **Network Testing**: Real packet capture and analysis
- **Performance Testing**: Load testing with multiple rules

### Test Data
- **Sample Rules**: Various rule types and complexities
- **Packet Captures**: Real network traffic samples
- **Attack Simulations**: Controlled attack scenarios

## Future Enhancements

### Planned Features
1. **Regex Support**: PCRE integration for content matching
2. **Rule Optimization**: Compile rules into more efficient structures
3. **Multi-threading**: Parallel packet processing
4. **GUI Interface**: Web-based rule management
5. **Rule Import/Export**: Standard rule formats

### Performance Improvements
1. **Rule Compilation**: Pre-compile rules for faster matching
2. **Packet Filtering**: BPF filter optimization
3. **Memory Pool**: Reduce allocation overhead
4. **Caching**: Cache frequently matched patterns

### Security Enhancements
1. **Rule Signatures**: Cryptographic rule validation
2. **Access Control**: User authentication and authorization
3. **Audit Logging**: Comprehensive activity logging
4. **Encryption**: Secure rule storage and transmission

## Development Guidelines

### Code Style
- **C99 Standard**: Use C99 features and syntax
- **Naming**: Descriptive variable and function names
- **Comments**: Document complex logic and algorithms
- **Error Handling**: Check return values and handle errors

### Testing Requirements
- **Unit Tests**: Test individual functions
- **Integration Tests**: Test component interactions
- **Performance Tests**: Measure and optimize performance
- **Security Tests**: Validate security assumptions

### Documentation
- **Code Comments**: Inline documentation for complex code
- **API Documentation**: Function and structure documentation
- **User Manual**: End-user documentation
- **Developer Guide**: Internal development documentation

## Known Issues

### Current Limitations
1. **No Regex**: Simple string matching only
2. **Single-threaded**: No parallel processing
3. **Basic Logging**: Simple file-based logging
4. **No GUI**: Command-line interface only
5. **Limited Protocols**: Basic IP, TCP, UDP, ICMP support

### Workarounds
1. **Content Matching**: Use multiple content rules for complex patterns
2. **Performance**: Optimize rule order for common cases
3. **Logging**: Use external log analysis tools
4. **Interface**: Use configuration files for complex setups
5. **Protocols**: Extend parser and engine for new protocols

## Team Responsibilities

### Core Parser Team
- **Lex Developer**: Maintain and extend lexer.l
- **Yacc Developer**: Maintain and extend parser.y
- **AST Developer**: Maintain ast.h and ast.c

### Backend Team
- **Engine Developer**: Maintain engine.h and engine.c
- **Integration Developer**: Maintain main.c and Makefile

### Documentation Team
- **Technical Writer**: Maintain README.md and documentation
- **Test Developer**: Create and maintain test cases

## Version History

### v1.0 (Current)
- Initial implementation
- Basic rule parsing
- Simple packet matching
- Console and file logging
- Command-line interface

### Planned v1.1
- Regex support
- Performance optimizations
- Enhanced error handling
- Additional rule options

### Planned v2.0
- Multi-threading
- GUI interface
- Advanced rule compilation
- Plugin architecture
