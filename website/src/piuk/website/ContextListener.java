package piuk.website;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

@WebListener
public class ContextListener implements ServletContextListener {

    public static boolean isShuttingDown = false;

    public void contextInitialized(ServletContextEvent sce) {
        System.out.println("contextInitialized()");

        try {
            SharedCoin.restore();
        } catch (Exception e) {
            e.printStackTrace();
        }


        OurWallet.scheduleTidyTasks();

        SharedCoin.exec.execute(new Runnable() {
            @Override
            public void run() {
                SharedCoin.checkIfProposalsAreBroadcastSuccessfully();
            }
        });
    }

    public void contextDestroyed(ServletContextEvent sce) {
        System.out.println("contextDestroyed()");

        isShuttingDown = true;
    }
}