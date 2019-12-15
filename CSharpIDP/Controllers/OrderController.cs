using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace CSharpIDP.Controllers
{
  [Authorize]
  [ApiController]
  [Route("[controller]")]
  public class OrderController : ControllerBase
  {
    private readonly ILogger<OrderController> _logger;

    public OrderController(ILogger<OrderController> logger)
    {
      _logger = logger;
    }

    [HttpGet]
    public IEnumerable<Order> Get()
    {
      var rng = new Random();
      return Enumerable.Range(1, 5).Select((index) => new Order
      (
        orderId: index,
        productId: index,
        productName: index.ToString(),
        orderDate: DateTime.Now.AddDays(index)
      ))
      .ToArray();
    }

    public class Order
    {
      public Order(int orderId, int productId, string productName, DateTime orderDate) =>
        (OrderId, ProductId, ProductName, OrderDate) = (orderId, productId, productName, orderDate);
      public int OrderId { get; }
      public int ProductId { get; }
      public string ProductName { get; }
      public DateTime OrderDate { get; }
    }
  }
}
