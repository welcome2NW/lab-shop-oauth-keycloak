package labshopoauthkeycloak.domain;

import java.util.Date;
import java.util.List;
import javax.persistence.*;
import labshopoauthkeycloak.OderApplication;
import labshopoauthkeycloak.domain.OrderPlaced;
import lombok.Data;

@Entity
@Table(name = "Order_table")
@Data
public class Order {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String productId;

    private Integer qty;

    private String customerId;

    private Double amount;

    @PostPersist
    public void onPostPersist() {
        OrderPlaced orderPlaced = new OrderPlaced(this);
        orderPlaced.publishAfterCommit();
    }

    @PrePersist
    public void onPrePersist() {}

    public static OrderRepository repository() {
        OrderRepository orderRepository = OderApplication.applicationContext.getBean(
            OrderRepository.class
        );
        return orderRepository;
    }
}
