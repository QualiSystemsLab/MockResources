if __name__ == "__main__":
    import mock
    shell_name = "Mockswitch"

    cancellation_context = mock.create_autospec(CancellationContext)
    context = mock.create_autospec(ResourceCommandContext)
    context.resource = mock.MagicMock()
    context.reservation = mock.MagicMock()
    context.connectivity = mock.MagicMock()
    context.reservation.reservation_id = "<RESERVATION_ID>"
    context.resource.address = "<RESOURCE_ADDRESS>"
    context.resource.name = "ayelet1"
    context.resource.attributes = dict()
    context.resource.attributes["{}.User".format(shell_name)] = "<USER>"
    context.resource.attributes["{}.Password".format(shell_name)] = "<PASSWORD>"
    context.resource.attributes["{}.SNMP Read Community".format(shell_name)] = "<READ_COMMUNITY_STRING>"
    context.resource.attributes["{}.num_modules".format(shell_name)] = "2"
    context.resource.attributes["{}.num_ports".format(shell_name)] = "3"
    context.resource.attributes["{}.power_ports".format(shell_name)] = "3"
    context.resource.attributes["{}.port_channels".format(shell_name)] = "4"

    driver = MockswitchDriver()
    # print driver.run_custom_command(context, custom_command="sh run", cancellation_context=cancellation_context)
    driver.initialize(context)
    result = driver.get_inventory(context)

    print "done"