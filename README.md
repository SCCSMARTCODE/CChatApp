# CChatApp  

CChatApp is a lightweight chat application built from scratch in C. It supports real-time communication between multiple computers using a client-server architecture. The project begins as a Command-Line Interface (CLI) application and is designed to evolve into a GUI-based chat platform.

## Features  
- **Phase 1**: Basic client-server messaging over TCP/IP.  
- **Phase 2**: Multi-client support with user identification.  
- **Phase 3**: Optional GUI integration using GTK or Qt.  
- **Phase 4**: Additional features like message encryption and file transfer.  

## Getting Started  

### Prerequisites  
- GCC or Clang compiler  
- Basic understanding of C programming  
- Knowledge of socket programming (helpful, but not mandatory)  

### Installation  
1. Clone the repository:  
   ```bash
   git clone https://github.com/your-username/CChatApp.git
   cd CChatApp
   ```  
2. Compile the application:  
   ```bash
   gcc -o server server.c  
   gcc -o client client.c  
   ```  
3. Run the server:  
   ```bash
   ./server
   ```  
4. Run the client (on the same or another machine):  
   ```bash
   ./client <server_ip>
   ```  

## Project Phases  

### Phase 1: CLI-Based Chat Application  
- [x] Basic client-server communication  
- [x] Support for sending and receiving messages  
- [ ] Error handling and user validation  

### Phase 2: Multi-Client Support  
- [ ] Threaded server to handle multiple clients  
- [ ] Broadcast messages to all connected clients  
- [ ] User disconnection handling  

### Phase 3: GUI Integration  
- [ ] Design a simple GUI using GTK or Qt  
- [ ] Add message input/output areas  
- [ ] Integrate GUI with networking logic  

### Phase 4: Advanced Features  
- [ ] Message encryption using OpenSSL  
- [ ] File transfer support  
- [ ] Chat themes and user preferences  

## Directory Structure  
```
CChatApp/  
│  
├── server.c         # Server-side code  
├── client.c         # Client-side code  
├── Makefile         # For building the project  
└── README.md        # Project documentation  
```  

## Contributing  
Contributions are welcome! Please follow these steps:  
1. Fork the repository.  
2. Create a new branch:  
   ```bash
   git checkout -b feature-name
   ```  
3. Commit your changes:  
   ```bash
   git commit -m "Add feature-name"
   ```  
4. Push to the branch:  
   ```bash
   git push origin feature-name
   ```  
5. Open a pull request.  

## License  
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.  

## Acknowledgments  
- *Beej's Guide to Network Programming* for socket programming resources.  
- The C programming community for their valuable tools and libraries.  

---
