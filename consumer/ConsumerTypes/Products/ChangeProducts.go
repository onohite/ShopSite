package Products

import (
	"consumer/db"
	"consumer/model"
	"encoding/json"
	"fmt"
	"github.com/streadway/amqp"
	"log"
)

func ListenChangeProducts(ch *amqp.Channel, service db.DBService) {
	q, err := ch.QueueDeclare(
		"changeProductQu", // name
		false,             // durable
		false,             // delete when unused
		false,             // exclusive
		false,             // no-wait
		nil,               // arguments
	)
	if err != nil {
		log.Fatalln(err)
	}

	if err = ch.QueueBind(
		"changeProductQu", // name of the queue
		"changeProduct",   // bindingKey
		"Shopper",         // sourceExchange
		false,             // noWait
		nil,               // arguments
	); err != nil {
		log.Fatalf("Queue Bind: %s", err)
	}

	msgs, err := ch.Consume(
		q.Name, // queue
		"",     // consumer
		true,   // auto-ack
		false,  // exclusive
		false,  // no-local
		false,  // no-wait
		nil,    // args
	)
	if err != nil {
		log.Fatalln(err)
	}

	go func() {
		for d := range msgs {
			fmt.Println(string(d.Body))
			var product model.Product
			err := json.Unmarshal(d.Body, &product)
			if err != nil {
				log.Println(err)
				continue
			}

			if err := service.ChangeProduct(product); err != nil {
				log.Println(err)
				continue
			}

			fmt.Printf("Продукт успешно отредактирован из очереди")
		}
	}()
}
