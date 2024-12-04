using Asp.Versioning;
using Logic;
using Microsoft.AspNetCore.Mvc;
using objects;
using question2.Interfaces;

namespace question2.Controllers.v0
{
    [Route("question2/v{version:apiversion}/")]
    [ApiVersion("0.0")]
    [ApiController]
    [Authorize]
    public class PaymentController(IPaymentLogic paymentLogic) : Controller
    {
        IPaymentLogic payment = paymentLogic;
        [HttpPost("initiate_payment")]
        public ActionResult InitiatePayment([FromBody] PaymentRequest request)
        {
            try
            {
                payment.InitiatePayment(request);
            }
            catch (Exception e)
            {
                throw;
            }
            
            return Ok();
        }

        [HttpGet("get_payment{paymentId}")]
        public ActionResult GetPayment(string paymentId)
        {
            try
            {
                payment.GetPayment(paymentId);
            }
            catch (Exception e)
            {
                throw;
            }

            return Ok();
        }

        [HttpGet("get_all_payments")]
        public ActionResult GetAllpayments()
        {
            return Ok( payment.GetAllPayments());
        }
    }
}