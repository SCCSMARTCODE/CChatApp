#include "client.h"


int main(int argc, char **argv) {

    clientDetails clientD;

    // integrating basic UI
    GtkWidget* window;
    GtkBuilder* builder;

    gtk_init(&argc, &argv);

    builder = gtk_builder_new_from_file(APP_UI_FILE_PATH);
    if (!builder) {
        g_printerr("Error loading .glade file\n");
        return 1;
    }

    window = GTK_WIDGET(gtk_builder_get_object(builder, "main_window"));
    g_signal_connect(window, "destroy", gtk_main_quit, NULL);
    gtk_builder_connect_signals(builder, NULL);
    gtk_widget_show_all(window);
    if (setupClientFromGUI(&clientD, builder) == -1) {
        LOG_ERROR("Client setup failed.");
        return EXIT_FAILURE;
    }


    pthread_t sendThread, receiveThread;
    SMData pack_ptr = {.data = &clientD, .builder = builder};

    if (pthread_create(&sendThread, NULL, sendMessagesWithGUI, &pack_ptr) != 0) {
        LOG_ERROR("Failed to create send thread: %s", strerror(errno));
        close(clientD.clientSocketFD);
        free(clientD.clientName);
        free(clientD.serverAddress);
        return EXIT_FAILURE;
    }
    LOG_SUCCESS("Send thread created successfully.");

    RMWGUI r_pack = {.clientD = &clientD, .builder = builder};
    if (pthread_create(&receiveThread, NULL, receiveMessagesWithGUI, &r_pack) != 0) {
        LOG_ERROR("Failed to create receive thread: %s", strerror(errno));

        pthread_cancel(sendThread);
        pthread_join(sendThread, NULL);

        close(clientD.clientSocketFD);
        free(clientD.clientName);
        free(clientD.serverAddress);
        return EXIT_FAILURE;
    }
    LOG_SUCCESS("Receive thread created successfully.");

    gtk_main();

    pthread_cancel(sendThread);
    pthread_cancel(receiveThread);
    pthread_join(sendThread, NULL);
    pthread_join(receiveThread, NULL);

    LOG_INFO("Client shutting down...");
    cleanup(&clientD);
    LOG_SUCCESS("Client shutdown complete.");
    return EXIT_SUCCESS;

    
    return EXIT_SUCCESS;
}