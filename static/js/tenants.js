function openEditTenantModal(tenant) {
  if (!tenant.id) {
    alert("Error: Tenant ID is missing. Cannot edit this tenant.");
    return;
  }
  document.getElementById('editTenantId').value = tenant.id || '';
 // document.getElementById('editTenantsName').value = tenant.tenants_name || '';
  document.getElementById('editTenantsPhone1').value = tenant.tenants_phone1 || '';
  document.getElementById('editTenantsPhone2').value = tenant.tenants_phone2 || '';
  document.getElementById('editTenantsEmail').value = tenant.tenants_email || '';
 // document.getElementById('editTenantsUsername').value = tenant.tenants_username || '';
  document.getElementById('editNationalId').value = tenant.national_id || '';
  document.getElementById('editCheckIn').value = tenant.check_in || '';
  document.getElementById('editCheckOut').value = tenant.check_out || '';
  document.getElementById('editRoomId').value = tenant.room_id || '';
  // Emergency contacts
  if (tenant.emergency_contacts && tenant.emergency_contacts.length > 0) {
    document.getElementById('editEmergencyContactName1').value = tenant.emergency_contacts[0].emergency_contact_name || '';
    document.getElementById('editEmergencyContactPhone1').value = tenant.emergency_contacts[0].emergency_contact_phone || '';
    document.getElementById('editEmergencyRelation1').value = tenant.emergency_contacts[0].relation || '';
  }
  if (tenant.emergency_contacts && tenant.emergency_contacts.length > 1) {
    document.getElementById('editEmergencyContactName2').value = tenant.emergency_contacts[1].emergency_contact_name || '';
    document.getElementById('editEmergencyContactPhone2').value = tenant.emergency_contacts[1].emergency_contact_phone || '';
    document.getElementById('editEmergencyRelation2').value = tenant.emergency_contacts[1].relation || '';
  }
  document.getElementById('editTenantModal').style.display = 'flex';
}
function closeEditTenantModal() {
  document.getElementById('editTenantModal').style.display = 'none';
}
function openShiftRoomModal(tenantId) {
  document.getElementById('shiftTenantId').value = tenantId;
  document.getElementById('shiftRoomModal').style.display = 'flex';
}
function closeShiftRoomModal() {
  document.getElementById('shiftRoomModal').style.display = 'none';
}
function toggleTenantDetails(card) {
  card.classList.toggle('expanded');
}